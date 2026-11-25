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

Key-pair objects keep private byte fields out of their default repr, but they still hold plaintext secret material in process memory. Do not serialize, log, print or persist these values. The encrypted keystore API is implemented separately; passphrase acquisition, key rotation, secure deletion and memory zeroization are not implemented.

## Error behavior

- Unsupported algorithms, malformed key encodings and invalid lengths raise `FormatError`.
- Failed signature verification returns `False`.
- Native backend/version failures raise `BackendUnavailable`.
- RSA-OAEP decryption/authentication failure raises `CryptoFailure`.

## Test coverage

The test suite exercises all enabled KEM/signature profiles, ML-KEM encapsulation/decapsulation, ML-DSA and SLH-DSA signing/verification, malformed inputs, X25519/P-256 ECDH, RSA-3072 OAEP/PSS, hybrid transcript/context binding, hybrid signature dual-verification, key fingerprints, encrypted keystore envelopes, streaming tamper/reorder/truncation, POSIX file-permission helpers and the security research scenarios. Passing tests do not establish side-channel resistance or suitability for production use.


## Encrypted private-key files

Private-key envelopes use Scrypt (N=2^15, r=8, p=1) to derive an AES-256-GCM key, a random 16-byte salt, a random 12-byte nonce, a versioned magic header, and authenticated caller-supplied associated data. The version/header and associated data are authenticated. Decryption fails closed on wrong passphrases, modified ciphertext, modified metadata, unknown versions, truncation, or malformed inputs.

The file API creates encrypted files atomically and refuses to overwrite an existing file. On Linux it enforces owner-only mode (0600). Loading rejects symlinks, unexpected file identity changes, and group/world permissions. The passphrase is supplied by the caller and is never persisted by this library. This protects key material at rest but does not protect it while unlocked in process memory.


## Streaming file encryption

The streaming format uses a versioned 32-byte header, HKDF-SHA-256 key derivation, AES-256-GCM per chunk, a random per-file salt and nonce prefix, and a 64-bit chunk counter. The default chunk size is 4 MiB and the hard maximum plaintext size is 1 TiB. Each chunk authenticates its index, length, protocol header and caller-supplied associated data. An authenticated final record is mandatory; truncation, reordering, duplication, modification, context mismatch and trailing bytes are rejected.

`decrypt_stream` spools authenticated chunks to a temporary file and publishes no plaintext to the destination until the final record and end-of-file are verified. The file helpers additionally create owner-only output files atomically and refuse to overwrite existing destinations. Use the file helpers when output publication must be all-or-nothing. The streaming functions operate on binary file-like objects; a failed encryption stream may contain a partial ciphertext and must be discarded.
