# Native and Python dependency provenance

## Locked baseline

| Component | Locked version / source | License | Verification |
|---|---|---|---|
| Python | 3.12.x | PSF | Runtime guard; tested on Python 3.12.16 |
| liboqs | 0.16.0, Git commit 5a1a854b0dc9f2141bdc771c555ee60c37950183 | MIT at root LICENSE.txt | Tag 0.16.0 resolves to this exact commit; local build is explicit |
| liboqs-python | 0.16.0.2 | MIT | PyPI wheel SHA-256 8e80da56cd409600a8366c5cf5099acd08eea4c031e4af225b63ba0c53433d76; Trusted Publishing provenance points to open-quantum-safe/liboqs-python commit 64c76ad0a80d6c69f2003219eb27b253782a3d68 |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | Exact version and platform wheel hashes are in uv.lock |
| pytest | 9.2.0 | MIT | Exact version and hashes are in uv.lock |
| Ruff | 0.17.6 | MIT | Exact version and hashes are in uv.lock |
| setuptools / wheel | 84.2.1 / 0.48.0 | MIT / MIT | Exact build-system versions are pinned in pyproject.toml |

The liboqs root LICENSE.txt states that individual third-party subfolders may carry different licenses. The inspected ML-KEM, ML-DSA and SLH-DSA algorithm directories in the pinned tag did not expose separate license files; the upstream root license is MIT. The project builds the upstream source locally and does not copy the native source into its own tracked tree. A full redistribution/third-party notice audit remains a release task in M11.

## Exact native allowlist

The native library is installed under .native/liboqs with an explicit OQS_MINIMAL_BUILD allowlist:
- KEM: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- Signatures: ML-DSA-44, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256s

In liboqs 0.16.0 the SLH-DSA backend identifiers are SLH_DSA_PURE_SHA2_128S, SLH_DSA_PURE_SHA2_192S and SLH_DSA_PURE_SHA2_256S. doctor maps these verified backend identifiers to the Design labels. Falcon, NTRU, NTRU-Prime, HQC, LMS and XMSS are not enabled. The operational default remains ML-KEM-768 + ML-DSA-65; research variants are exposed only through the separately allowlisted lab. The build does not expose the legacy Kyber or SPHINCS+ names.

The default operational suite is not replaced if a variant is missing. doctor reports optional algorithms separately; missing ML-KEM-768 or ML-DSA-65 is fatal.

## Advisory assessment (checked 2026-11-25)

| Advisory | Upstream scope / fix | Project exposure and mitigation |
|---|---|---|
| GHSA-jr5q-r9qx-v738 / CVE-2026-47738 | liboqs before 0.16.0; uninitialized function-pointer dereference only when OQS_KEM_encaps_derand is called for six NTRU-HPS/NTRU-HRSS variants; fixed in 0.16.0 | Pin 0.16.0; minimal build excludes all NTRU KEMs; application allowlist never calls derandomized NTRU encapsulation |
| GHSA-w696-4vrr-x6x3 | liboqs-python <=0.16.0.1; short public keys, ciphertexts and secret keys could be zero-padded; fixed in 0.16.0.2 | Pin 0.16.0.2; future PQC wrappers still validate every input length against runtime metadata before native calls |
| GHSA-pw23-r5gj-42g8 | Shell command injection in liboqs-python automatic native installation; fixed in 0.16.0.1 | Pin 0.16.0.2 and additionally block the import-time install fallback in require_backend |
| GHSA-xv6c-h66p-6mfq | liboqs <=0.16.0; LMS stateful signing lock failures could permit LM-OTS key reuse; fixed in 0.17.0 | LMS is explicitly disabled and absent from the minimal build; this project does not use stateful signatures |
| GHSA-wh5q-mpc8-67wf / CVE-2026-104254 | liboqs <=0.16.0 with OQS_ENABLE_SIG_STFL_LMS=ON; out-of-bounds read in LMS/HSS verification; fix scheduled for 0.17.0 | LMS is explicitly disabled; no LMS/HSS verification API is exposed |
| GHSA-2wxh-55qf-c7wg / CVE-2026-46344 | liboqs <=0.15.0; XMSS OID/parameter mismatch in verification; fixed in 0.16.0 | Version is fixed; XMSS is also disabled and not used |
| GHSA-wf7v-fhxj-73m2 | liboqs 0.15.0; XMSS short-signature overread; fixed in 0.16.0 | Version is fixed; XMSS is disabled |
| GHSA-qq3m-rq9v-jfgm, GHSA-3rxw-4v8q-9gq5, GHSA-gpf4-vrrw-r8v7 | HQC timing/design/correctness advisories | HQC is excluded from the exact native allowlist |
| GHSA-f2v9-5498-2vpp | Legacy Kyber reference implementation timing issue | Only standardized ML-KEM identifiers are built and exposed |

Sources:
- liboqs 0.16.0 release: https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0
- liboqs-python 0.16.0.2 release: https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.2
- GHSA-jr5q-r9qx-v738: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-jr5q-r9qx-v738
- GHSA-w696-4vrr-x6x3: https://github.com/open-quantum-safe/liboqs-python/security/advisories/GHSA-w696-4vrr-x6x3
- GHSA-pw23-r5gj-42g8: https://github.com/open-quantum-safe/liboqs-python/security/advisories/GHSA-pw23-r5gj-42g8
- GHSA-xv6c-h66p-6mfq: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-xv6c-h66p-6mfq
- GHSA-wh5q-mpc8-67wf: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-wh5q-mpc8-67wf
- GHSA-2wxh-55qf-c7wg: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-2wxh-55qf-c7wg
- GHSA-wf7v-fhxj-73m2: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-wf7v-fhxj-73m2

The liboqs security-advisory page and package release notes were checked on 2026-11-25. This is a point-in-time assessment, not a claim that the dependencies are vulnerability-free. Recheck advisories before release and before updating any pinned dependency.

## Loader and no-auto-install contract

Upstream liboqs-python imports its native library at module import. If it cannot load liboqs, its fallback creates a temporary directory, sleeps, clones liboqs and invokes CMake. OQS_INSTALL_PATH selects a search prefix; it is not a disable-auto-install switch.

This project therefore:
1. has doctor inspect the explicit shared-library path using ctypes, call OQS_version and query only the approved algorithm identifiers without importing oqs;
2. fails before import if the shared library, exact versions or default algorithms are missing;
3. temporarily sets OQS_INSTALL_PATH to the checked prefix and restricts oqs lookup to that prefix;
4. blocks subprocess execution and the install countdown on the importing thread during the wrapper import;
5. verifies the wrapper/native versions and the exact loaded library path after import.

The real import smoke test succeeds with subprocess execution denied. The missing-library test runs in an isolated subprocess with socket connection and subprocess execution denied and verifies that no oqs import or filesystem installation occurs.

## Explicit provisioning

Run scripts/provision-linux.sh from the repository on Linux x86_64. It:
1. runs uv sync --locked --extra dev so Python distributions are checked against uv.lock hashes;
2. clones the exact liboqs tag and checks its full commit SHA;
3. configures the exact OQS_MINIMAL_BUILD allowlist as a shared library;
4. installs into the ignored .native directory without sudo or system-wide writes;
5. runs scripts/check-native.py and exits nonzero if the real doctor is not ready.

The application never downloads, compiles or upgrades liboqs at runtime. If the library is absent, incompatible or missing a default algorithm, doctor exits nonzero and crypto entry points must raise BackendUnavailable.
