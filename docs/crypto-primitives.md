# Cryptographic primitive API

This module is a research interface over the pinned liboqs and PyCA backends. It is not a production cryptographic module, FIPS-validated implementation, or complete protocol.

## Post-quantum algorithms

- ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA-44, ML-DSA-65, ML-DSA-87
- SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256s

Default profile: ML-KEM-768 and ML-DSA-65. SLH-DSA public Design labels are mapped to liboqs 0.16.0's `SLH_DSA_PURE_SHA2_*` backend identifiers.

All operations validate key/ciphertext lengths against runtime metadata before native calls. Unknown and legacy aliases (for example Kyber and Dilithium names) are rejected.

## Classical algorithms

- X25519 and P-256 ECDH
- ECDSA P-256 with SHA-256
- RSA-3072 OAEP with SHA-256/MGF1-SHA-256 and a fixed protocol label
- RSA-3072 PSS with SHA-256/MGF1-SHA-256 and maximum salt length

RSA OAEP is a bounded key-transport primitive, not a bulk-data encryption API.

## Hybrid profiles

Default hybrid KEM: ML-KEM-768 + X25519.

The two independently derived shared secrets are length-framed and fed to HKDF-SHA-256. The transcript binds the protocol domain/version, algorithm, recipient public keys, KEM ciphertext, ephemeral X25519 public key and caller context. It does not concatenate the secrets as the final key, XOR them, or silently fall back to a classical-only/PQ-only result.

Hybrid signature profile: ML-DSA-65 + ECDSA-P256. Both signatures cover the same domain-separated, context-bound message; verification succeeds only if both components verify.

## Secret-key handling

Key-pair objects keep private byte fields out of their default repr, but they still hold plaintext secret material in process memory. Do not serialize, log, print or persist these values. Encrypted private-key storage and lifecycle controls belong to the key-management milestone and are not implemented by this primitive layer.

## Error behavior

- Unsupported algorithms, malformed key encodings and invalid lengths raise `FormatError`.
- Failed signature verification returns `False`.
- Native backend/version failures raise `BackendUnavailable`.
- RSA-OAEP decryption/authentication failure raises `CryptoFailure`.

## Test coverage

The test suite exercises all six enabled KEM/signature profiles, ML-KEM encapsulation/decapsulation, ML-DSA and SLH-DSA signing/verification, malformed inputs, X25519/P-256 ECDH, RSA-3072 OAEP/PSS, hybrid transcript/context binding, and hybrid signature dual-verification. Passing tests do not establish side-channel resistance or suitability for production use.
