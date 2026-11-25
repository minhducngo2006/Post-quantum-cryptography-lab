# Changelog

All notable project changes are recorded here. This project is pre-1.0 research software.

## 0.1.0 — 2026-11-25 (local release candidate; not published)

- Added an explicitly provisioned, pinned liboqs 0.16.0 backend with fail-closed preflight and Linux CI.
- Added ML-KEM, ML-DSA, and SLH-DSA profiles plus classical ECDH, ECDSA, and RSA primitives.
- Added hybrid ML-KEM/X25519 key establishment and ML-DSA/ECDSA dual signatures.
- Added Scrypt/AES-256-GCM private-key envelopes and authenticated chunked file encryption.
- Added real-operation benchmark exports and a Textual research dashboard.
- Added synthetic adversarial research scenarios, public-key fingerprints, and bounded parser fuzzing.
- Added Linux deployment, architecture, security, benchmark, and research documentation.
- Added MIT licensing, source distribution metadata, and local release checksums.

### Release caveats

- Linux x86_64 is the only supported and verified target.
- No FIPS validation, formal protocol proof, independent cryptographic audit, constant-time audit, or physical side-channel assessment is claimed.
- This release candidate has not been tagged, published to a package index, or merged to the default branch.
