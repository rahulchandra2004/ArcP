"""
Reversible Redaction Vault with TTL-based In-Memory Storage.
Implements regex + Shannon entropy secret detection and bidirectional tokenization.
"""
from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


def calculate_shannon_entropy(data: str) -> float:
    """Compute Shannon entropy H(X) = -sum(P(x) * log2(P(x))) for a string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class VaultEntry:
    token: str
    original: str
    category: str
    created_at: float
    ttl: float = 600.0  # 10 minutes

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl


class TokenVault:
    """
    Thread-safe, in-memory bidirectional redaction vault.
    Dehydrates sensitive data into deterministic tokens and safely re-hydrates them.
    """

    DEFAULT_TTL: float = 600.0  # 10 minutes

    # Regex patterns for high-risk PII and credentials
    _PATTERN_AWS_KEY = re.compile(r"\b(AKIA|ABIA|ACCA)[0-9A-Z]{16}\b")
    _PATTERN_GITHUB = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b")
    _PATTERN_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
    _PATTERN_PRIVATE_KEY = re.compile(
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
    )
    _PATTERN_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _PATTERN_IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    _PATTERN_IPV6 = re.compile(
        r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"
    )
    _PATTERN_PHONE = re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    )
    # Generic high-entropy token candidate word (min 16 chars)
    _PATTERN_WORD_TOKEN = re.compile(r"\b[A-Za-z0-9_\-\.]{16,}\b")

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._lock = threading.RLock()
        self._token_to_entry: Dict[str, VaultEntry] = {}
        self._secret_to_token: Dict[str, str] = {}
        self._category_counters: Dict[str, int] = {
            "SECRET": 0,
            "IP": 0,
            "EMAIL": 0,
            "PHONE": 0,
        }
        self._total_scrubbed: int = 0
        self._total_rehydrated: int = 0

    @property
    def total_scrubbed(self) -> int:
        with self._lock:
            return self._total_scrubbed

    @property
    def total_rehydrated(self) -> int:
        with self._lock:
            return self._total_rehydrated

    def prune_expired(self) -> int:
        """Evict expired vault tokens based on TTL."""
        with self._lock:
            now = time.time()
            expired_tokens = [
                token for token, entry in self._token_to_entry.items()
                if (now - entry.created_at) > entry.ttl
            ]
            for token in expired_tokens:
                entry = self._token_to_entry.pop(token, None)
                if entry and entry.original in self._secret_to_token:
                    del self._secret_to_token[entry.original]
            return len(expired_tokens)

    def _allocate_token(self, secret: str, category: str) -> str:
        """Allocate or retrieve an existing deterministic token for the secret."""
        if secret in self._secret_to_token:
            token = self._secret_to_token[secret]
            # Refresh entry timestamp
            if token in self._token_to_entry:
                self._token_to_entry[token].created_at = time.time()
            return token

        self._category_counters[category] = self._category_counters.get(category, 0) + 1
        idx = self._category_counters[category]
        token = f"<ARCP_{category}_{idx}>"

        entry = VaultEntry(
            token=token,
            original=secret,
            category=category,
            created_at=time.time(),
            ttl=self._ttl,
        )
        self._token_to_entry[token] = entry
        self._secret_to_token[secret] = token
        return token

    def scrub_and_store(self, text: str) -> Tuple[str, int]:
        """
        Dehydrate text by replacing secrets, PII, and high-entropy strings with tokens.
        Returns: (sanitized_text, count_of_redactions)
        """
        if not text:
            return text, 0

        with self._lock:
            self.prune_expired()
            redaction_count = 0
            # Order matters: private keys and multiline secrets first
            matches: List[Tuple[int, int, str, str]] = []  # (start, end, secret, category)

            # 1. Private keys
            for m in self._PATTERN_PRIVATE_KEY.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "SECRET"))

            # 2. AWS keys
            for m in self._PATTERN_AWS_KEY.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "SECRET"))

            # 3. GitHub tokens
            for m in self._PATTERN_GITHUB.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "SECRET"))

            # 4. JWTs
            for m in self._PATTERN_JWT.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "SECRET"))

            # 5. Emails
            for m in self._PATTERN_EMAIL.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "EMAIL"))

            # 6. IPv4
            for m in self._PATTERN_IPV4.finditer(text):
                val = m.group(0)
                # Ignore loopback 127.0.0.1 or standard 0.0.0.0 if desired, or scrub all
                matches.append((m.start(), m.end(), val, "IP"))

            # 7. IPv6
            for m in self._PATTERN_IPV6.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "IP"))

            # 8. Phones
            for m in self._PATTERN_PHONE.finditer(text):
                matches.append((m.start(), m.end(), m.group(0), "PHONE"))

            # 9. High-Entropy Tokens (H > 4.2, length >= 16)
            for m in self._PATTERN_WORD_TOKEN.finditer(text):
                val = m.group(0)
                entropy = calculate_shannon_entropy(val)
                if entropy > 4.2:
                    matches.append((m.start(), m.end(), val, "SECRET"))

            if not matches:
                return text, 0

            # Sort matches by start index ascending, resolve overlaps
            matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
            non_overlapping: List[Tuple[int, int, str, str]] = []
            last_end = -1
            for start, end, secret, cat in matches:
                if start >= last_end:
                    non_overlapping.append((start, end, secret, cat))
                    last_end = end

            # Build sanitized text from non-overlapping spans
            result_parts: List[str] = []
            curr_pos = 0
            for start, end, secret, cat in non_overlapping:
                result_parts.append(text[curr_pos:start])
                token = self._allocate_token(secret, cat)
                result_parts.append(token)
                curr_pos = end
                redaction_count += 1

            result_parts.append(text[curr_pos:])
            sanitized = "".join(result_parts)
            self._total_scrubbed += redaction_count
            return sanitized, redaction_count

    def rehydrate(self, text: str) -> Tuple[str, int]:
        """
        Scan incoming text and restore all <ARCP_*> tokens back to original values in memory.
        Returns: (restored_text, count_of_rehydrations)
        """
        if not text:
            return text, 0

        with self._lock:
            self.prune_expired()
            restore_count = 0

            def _repl(match: re.Match) -> str:
                nonlocal restore_count
                token = match.group(0)
                entry = self._token_to_entry.get(token)
                if entry is not None and not entry.is_expired:
                    restore_count += 1
                    return entry.original
                return token

            # Match any <ARCP_[A-Z]+_[0-9]+>
            token_pattern = re.compile(r"<ARCP_[A-Z0-9_]+>")
            restored = token_pattern.sub(_repl, text)
            self._total_rehydrated += restore_count
            return restored, restore_count

    def clear(self) -> None:
        """Wipe all vault contents from RAM."""
        with self._lock:
            self._token_to_entry.clear()
            self._secret_to_token.clear()
            self._category_counters = {"SECRET": 0, "IP": 0, "EMAIL": 0, "PHONE": 0}
