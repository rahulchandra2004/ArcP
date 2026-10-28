# ArcP Nightly Security & Benchmark CI Telemetry

![Security CI](https://img.shields.io/badge/Security_CI-Passing-brightgreen)
![PyTest Regression](https://img.shields.io/badge/PyTest-31%2F31_Passed-blue)
![SHA-256 Signatures](https://img.shields.io/badge/SHA--256_Signatures-Verified-success)
![Platform](https://img.shields.io/badge/Platform-Headless_Linux_%2F_Windows-00F5D4)

This telemetry document is automatically published by the **ArcP Nightly Security & Benchmark CI** workflow. It records real-time sub-millisecond execution benchmarks, pytest regression passes, and cryptographic SHA-256 integrity signatures across all radial operational modules.

---

### Environment & Run Metadata
* **Execution Timestamp:** `2026-10-28T18:55:32Z`
* **Host Operating System:** `Linux 7.0.0-1017-azure`
* **Python Runtime:** `Python 3.11.17`
* **Execution Engine:** Headless Offscreen Pipeline (`QT_QPA_PLATFORM=offscreen`)
* **Core Version:** `ArcP v1.1.0.0`

---

### Sub-Millisecond Latency Benchmarks
| Component | Metric | Mean Latency | Throughput | SLA Threshold | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TokenVault Shannon Entropy** | In-Memory Secret Detection | `0.0033 ms` | ~`303,764 ops/s` | `< 1.0000 ms` | **PASSED** |
| **MimeRouter Header Sniffer** | Polymorphic Magic Byte Check | `0.0019 ms` | ~`517,368 ops/s` | `< 10.0000 ms` | **PASSED** |

---

### Test Regression Suite
* **Suite File:** `tests/test_pipeline.py`
* **Test Results:** **`31 / 31` Passed** (100% compliance)
* **Suite Execution Time:** `545.13 ms` (`0.55s`)
* **Zero-Disk Pipeline:** All test artifacts, token dehydration vaults, and clipboard events executed entirely in-memory.

---

### Cryptographic File Integrity Manifest (SHA-256)
All production modules under `core/`, `plugins/`, and `ui/` are audited against unauthorized tampering and drift:

| Module Path | SHA-256 Checksum | Audit Result |
| :--- | :--- | :--- |
| `core/__init__.py` | `3967663fb5b188a0093238e8d2dc107110c7d68690db7551fdc817d4f3ca7472` | Verified |
| `core/clipboard_pipe.py` | `e139a6fe4c9cb778f2d8aa80431b011b9785731e51233c9ebdbb670658bae040` | Verified |
| `core/gravity_well.py` | `dfaebccbc08dff45e6e964dda2c403d4191ce05f4ebe0ac937181290d8f190c9` | Verified |
| `core/mime_router.py` | `574dc2d4c82d7989dd5e785cf36055cec94ef41471c519dc9346a97221266de6` | Verified |
| `core/telemetry.py` | `5728e71f167fd9f5cf48a265f0616141e1ec76ed22b9a54fc7d78dc69f58415c` | Verified |
| `core/token_vault.py` | `1e336463bfef94541c0f17ae5826ced3735c62ab7b6bf2d0dacaad88fbbb953d` | Verified |
| `core/worker_pool.py` | `0fc4a1d8d55ce665147528344eb69327bc091c775402732508761ff9256c5707` | Verified |
| `plugins/__init__.py` | `a9dab48de00e2f1b686ea3e72280b67c6ee55982f43a6e1d13d09fd03d2f5ebe` | Verified |
| `plugins/base_plugin.py` | `7e084ff6501d9e1daf340b842a62c41272d9eae9e9e6fb22a41496544d5490a3` | Verified |
| `plugins/binary_ops.py` | `d82b42a72ebc02f9bc28c182b545527efe3b9bdcf6c38346843dd739735563d5` | Verified |
| `plugins/code_log_ops.py` | `a4551076c85e47c42a832852b53e023ba9560f3f5c585a80aa26427c704f53f4` | Verified |
| `plugins/data_ops.py` | `42f9b9bbace4651fdf22d0ee86b5bdb186291bd806f36986b9c657575dc88e5f` | Verified |
| `plugins/git_ops.py` | `b217f3960f6dc48ff185e4401dc5b049b7544b5aacf0ad5f70fba5ac408eeaae` | Verified |
| `plugins/image_ops.py` | `1a220a463f1ebdf832a41a7dd0a3f78120e7c0ebe379026089fbd0e7a16b6235` | Verified |
| `plugins/infra_ops.py` | `c20c735abf3e9a6fb29f8d2154121c2c3a5e5b8f04eec0aecbefcb46e5f73588` | Verified |
| `plugins/ml_ops.py` | `69c36353dc40626118bb6342539704023d0d53560145bfc32fee084a036d11b9` | Verified |
| `ui/__init__.py` | `6e6e1ecf04cf4411a1b44d9592590db1619979753c7086fc5dd6a8b6ad693828` | Verified |
| `ui/animations.py` | `57fa3a9fce7670faab26c2406b7290fb8913f1357f8fcd31ec10d5117e71f3de` | Verified |
| `ui/cursor_watcher.py` | `93631984403917a8cc7eb8cada4e15a2c19f7d9e5265a3343c03d0f89d73c2ae` | Verified |
| `ui/geometry.py` | `d670d46d534bc853a9b86f615955b2f436899129f458524bab87c41ead4e5a69` | Verified |
| `ui/icons.py` | `e8d0373fdc73b46fda6c9276dd4dc98405f93a50bee1bb2c3a63680ff2501a44` | Verified |
| `ui/inspector_drawer.py` | `0a9ce3f6d841d72dccde9283617cfa1389f0ea880768eca6d9a8b232cf3df83b` | Verified |
| `ui/radial_window.py` | `c8bf6b59d248e2ba9e9d9fd130051b1567d5bafe61667803a235344847cac324` | Verified |

---
*Generated automatically by ArcP Automated CI/CD Engine (`scripts/generate_telemetry.py`).*
