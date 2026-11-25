# PQC Lab — portfolio summary

## One-line description

A Linux-based Python research lab for post-quantum cryptography, hybrid key establishment/signatures, authenticated file encryption, adversarial security experiments, benchmarking, and an interactive terminal dashboard.

## Technical highlights

- **Native supply chain:** pinned liboqs 0.16.0 and liboqs-python 0.16.0.2; explicit provisioning, algorithm allowlisting, fail-closed preflight, and runtime auto-install blocked.
- **Post-quantum primitives:** ML-KEM, ML-DSA, and SLH-DSA profiles backed by Open Quantum Safe liboqs.
- **Hybrid cryptography:** ML-KEM-768 + X25519 with transcript-bound HKDF-SHA-256; ML-DSA-65 + ECDSA-P256 with mandatory dual verification.
- **Encrypted storage:** Scrypt + AES-256-GCM private-key envelopes with authenticated metadata and owner-only Linux file permissions.
- **Streaming integrity:** authenticated AES-GCM records with index/context binding and a mandatory final record to detect truncation.
- **Security research:** seven synthetic adversarial scenarios and a bounded Atheris parser-fuzz target.
- **Performance visibility:** real ML-KEM/ML-DSA operations with raw samples, JSON/CSV exports, and latency charts.
- **Usability:** Textual dashboard for backend status, algorithm availability, research outcomes, and benchmark telemetry.

## Evidence

- [Architecture](architecture.md)
- [Cryptographic API](crypto-primitives.md)
- [Security research design](security-research.md)
- [Measured benchmark and adversarial results](research-report.md)
- [Linux deployment guide](deployment.md)

The recorded 2026-11-25 Ubuntu/WSL2 run completed 83 automated tests, passed all seven security scenarios, rejected all ten malformed parser corpus inputs, and completed a 100-run Atheris smoke without a crash. The benchmark report contains raw samples and environment metadata.

## CV-ready bullets

- Built a Linux-based post-quantum cryptography toolkit in Python using ML-KEM, ML-DSA, SLH-DSA, and a pinned Open Quantum Safe liboqs backend.
- Implemented hybrid ML-KEM-768/X25519 key establishment and ML-DSA-65/ECDSA-P256 dual signatures with transcript binding and HKDF-SHA-256.
- Developed authenticated AES-256-GCM key storage and chunked file encryption, plus adversarial security experiments, bounded fuzzing, benchmarking, and a Textual dashboard.
- Verified the implementation with 83 automated tests on Ubuntu/WSL2.

## Responsible claims

This is research/education software, not production cryptography. It is not FIPS validated and has not undergone formal protocol analysis, independent cryptographic audit, constant-time review, physical side-channel testing, secure deletion, or memory zeroization assessment. Linux x86_64 is the only supported target.
