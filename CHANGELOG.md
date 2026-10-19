# ArcP Changelog

All notable changes to the Autonomous Radial Context Pipeline (ArcP) are documented in this file.

---

## [v1.1.0.0] - The Solid Matte UI & Inspector Drawer Update

![build passing](https://img.shields.io/badge/build-passing-brightgreen)
![Platform Windows](https://img.shields.io/badge/Platform-Windows-00F5D4)

### Core Features & Enhancements
* **100% Solid Matte Industrial Dark UI:** Migrated from translucent glassmorphism to an opaque solid matte industrial dark UI (`#090D16` Obsidian, `#111827` Slate) with zero desktop background bleed.
* **Frameless Solid Matte Inspector Drawer (`ui/inspector_drawer.py`):** Hardware-accelerated diagnostic viewport displaying rich Markdown tables, syntax-highlighted code blocks, high-DPI image previews, and one-click clipboard copying.
* **High-DPI Retina Vector Icons (`ui/icons.py`):** Procedural anti-aliased 64x64 vector icons with device pixel ratio supersampling and distinct icons across all 28 slices.
* **Type-Annotated AST Constants:** Extended AST symbol auditor with `ast.AnnAssign` parsing to capture type-annotated module constants (`DEFAULT_TTL: float = 600.0`).

### Bug Fixes & Stability
* Removed double-inset border artifacts on concentric sub-slices.
* Expanded slice text bounding height to 54px with concise 1-line headers so 2-line titles never push subtitles out of frame.
* Eliminated duplicate icons across same-ring slices and resolved slice click event routing inside the main HUD.

---

## [v1.0.2.0] - Sticky Mode Lock & Python AST Symbol Audit Update

![build passing](https://img.shields.io/badge/build-passing-brightgreen)
![Platform Windows](https://img.shields.io/badge/Platform-Windows-00F5D4)

### Core Features & Enhancements
* **Manual Mode Pinning (PINNED State):** Added sticky mode locking (`PINNED` state) so manual mode switches via scroll wheel, center click, keys 1-7, or context menu are never overridden by `dragEnterEvent` auto-routing.
* **Python AST Symbol & Dependency Audit:** Upgraded `BINARY` Symbol Audit (`01`) with a Python `ast` parser to extract classes, methods, imports, constants, and foreign C/C++ bindings from dropped `.py` and script files.
* **Script & Runtime Header X-Ray:** Added detailed encoding, BOM, CRLF/LF line endings, shebang (`#!`), first 64-byte canonical hex dump, and Shannon byte entropy analysis for non-binary source files.
* **Async QThreadPool Workers:** Non-blocking asynchronous worker pipeline to eliminate UI freezes during heavy cryptographic or computer vision actions.

### Bug Fixes & Stability
* Fixed radial text overflow across left/right slices using strict `QPainter.setClipPath` sector boundaries.
* Implemented pixel-accurate `QFontMetrics.elidedText` to prevent text overlap in compact radial slices.

---

## [v1.0.1.0] - Native WinRT Neural OCR & Lazy-Loader Update

![build passing](https://img.shields.io/badge/build-passing-brightgreen)
![Platform Windows](https://img.shields.io/badge/Platform-Windows-00F5D4)

### Core Features & Enhancements
* **Windows Native WinRT Neural OCR:** Replaced external OCR dependencies with zero-dependency Windows Native WinRT Neural OCR (`Windows.Media.Ocr`) for targeted PII/Secret bounding-box redaction in screenshots.
* **LazyModule Proxy Loader:** Defer heavy module imports to cut cold startup latency down to <150ms.
* **System Tray & Windowed Mode:** Added system tray notification area presence and `--windowed` launch mode for standard taskbar window operation.
* **Intelligent Targeted PII Redaction:** Computer vision engine blurring email addresses, API tokens, credentials, and facial bounding boxes while keeping UI elements crisp.

### Bug Fixes & Stability
* Fixed invisible/minimized startup window by properly centering the Expanded HUD on the primary monitor.
* Resolved Windows cp1252 `UnicodeEncodeError` terminal crashes via automatic UTF-8 console stream reconfiguration.
* Wrapped image decoding in diagnostic exception guards to prevent `UnidentifiedImageError` crashes on non-image payloads.

---

## [v1.0.0.0] - Initial Core Pipeline Release

![build passing](https://img.shields.io/badge/build-passing-brightgreen)
![Platform Windows](https://img.shields.io/badge/Platform-Windows-00F5D4)

### Core Features & Enhancements
* **7 Polymorphic Radial Modes:** Instant desktop context routing across `CODE_LOG`, `GIT_PATCH`, `ML_MODEL`, `BINARY`, `IMAGE`, `DATASET`, and `INFRA`.
* **28 Specialized Action Slices:** Micro-actions for token redaction, container generation, schema extraction, and diff analysis.
* **Zero-Disk In-Memory Clipboard Pipe:** Direct RAM-to-clipboard streaming via `io.BytesIO` and `QClipboard` with zero temporary disk footprint.
* **Reversible TokenVault:** Ephemeral in-memory credential and secret vault with automated TTL expiry and Shannon entropy scanning.
* **Deterministic Test Suite:** Complete end-to-end `pytest` verification suite covering polar geometry and MIME routing.

### Bug Fixes & Stability
* Initial cross-platform window geometry initialization and coordinate normalization.
* Robust fallback handling for clipboard MIME routing baseline.
