# PQC Security Research Results

- Run: `20261125T153302Z-89a9a2c1`
- Created: 2026-11-25T15:33:02.490386+00:00
- Python: 3.12.16
- liboqs: 0.16.0
- liboqs-python: 0.16.0.2
- Overall: PASS

| Scenario | Expected behavior | Observed behavior | Result |
|---|---|---|---|
| Tampered hybrid KEM ciphertext | Tampering must not reproduce the sender's shared secret. | Implicit rejection produced a different receiver secret. | PASS |
| Protocol version and algorithm downgrade | Unsupported versions and suite substitution must raise FormatError. | 2/2 downgrade attempts rejected. | PASS |
| Recipient public-key substitution | A substituted recipient key must have a different fingerprint and fail key agreement. | Fingerprint mismatch detected; substituted recipient derived a different secret. | PASS |
| Hybrid signature component stripping | Verification must fail if either ML-DSA or ECDSA is absent. | PQ component rejected=True; classical component rejected=True. | PASS |
| Encrypted chunk reordering | Reordered authenticated records must fail authentication. | Reordered records rejected. | PASS |
| Authenticated final-record truncation | A missing final authentication tag must reject the complete stream. | Truncated final record rejected. | PASS |
| Bounded malformed-envelope parser corpus | Every malformed corpus input must be rejected without an unhandled parser exception. | 10/10 malformed inputs rejected; fuzz target caps input at 1 MiB and plaintext at 8 MiB. | PASS |

All fixtures use newly generated ephemeral keys and synthetic messages. No caller keys, passphrases, plaintext files, or shared secrets are written to the report.

This is a research harness, not a production security certification or side-channel assessment.
