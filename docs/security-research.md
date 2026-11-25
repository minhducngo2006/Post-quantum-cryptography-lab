# Security Research Lab

This milestone runs reproducible adversarial experiments against the lab's public cryptographic interfaces. Every run creates new ephemeral keys and synthetic messages. It does not accept caller-supplied keys, read private files, use real user data, or print secret material.

## Deterministic experiments

Run the suite and export a sanitized JSON/Markdown report:

```bash
OQS_INSTALL_PATH="$PWD/.native/liboqs" uv run --locked pqclab research \
  --output-dir ./research-results
```

The report covers:

| Scenario | Expected security behavior |
|---|---|
| Ciphertext tampering | ML-KEM implicit rejection must not reproduce the sender's shared secret |
| Protocol downgrade | Unsupported versions and algorithm substitution are rejected |
| Recipient-key substitution | The hybrid public-key fingerprint changes and the substituted recipient derives a different secret |
| Hybrid signature stripping | Removing either ML-DSA or ECDSA makes verification fail |
| Stream chunk reordering | Record index binding causes authentication failure |
| Stream truncation | A missing final authentication tag rejects the complete stream |
| Parser fuzz corpus | Malformed headers/records are rejected without unhandled parser exceptions |

The suite uses bounded synthetic payloads and exports only scenario IDs, expected/observed behavior, pass/fail status, and runtime version metadata. It never exports keys, ciphertexts, plaintexts, or passphrases.

## Bounded parser fuzzing

Install the pinned Linux-only Atheris extra and run the streaming parser target:

```bash
uv sync --locked --extra fuzz
OQS_INSTALL_PATH="$PWD/.native/liboqs" uv run --locked --extra fuzz \
  python scripts/fuzz_stream_parser.py
```

The target enforces:
- maximum fuzz input: 1 MiB
- maximum decrypted plaintext: 8 MiB
- maximum total runtime: 30 seconds
- maximum RSS: 512 MiB
- per-input timeout: 5 seconds
- maximum executions: 10,000

Smaller limits can be supplied using standard libFuzzer flags, for example `-runs=100`. The script rejects attempts to raise any hard limit. Unexpected exceptions are not swallowed, so Atheris can report parser crashes. Expected `FormatError` and `CryptoFailure` outcomes are treated as rejected malformed inputs.

## Interpretation and limitations

ML-KEM decapsulation is designed with implicit rejection: a modified but correctly sized ciphertext may return a pseudorandom secret rather than raising an exception. The tampering experiment therefore checks that the receiver does not derive the sender's secret; it does not claim that decapsulation throws.

These tests do not establish constant-time behavior, resistance to physical side channels, formal protocol security, or production readiness. They are a bounded research harness for the specific attack cases above.
