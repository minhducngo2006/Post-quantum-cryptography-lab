# Release checklist — 0.1.0

This is a local Linux release-candidate checklist. It does not publish or tag the repository.

## Completed locally

- [x] Project metadata declares Python 3.12 and MIT licensing.
- [x] Linux x86_64 target and Ubuntu/WSL2 setup documented.
- [x] Pinned liboqs 0.16.0 provisioner and fail-closed backend preflight.
- [x] Locked dependency resolution checked with `uv lock --check`.
- [x] Ruff lint and format checks pass.
- [x] Linux/WSL2 test suite passes (83 tests on 2026-11-25).
- [x] Pinned native backend doctor reports ready with all required algorithms enabled.
- [x] Seven synthetic security research scenarios pass.
- [x] Bounded Atheris smoke completes 100 runs without a crash.
- [x] Benchmark JSON/CSV/PNG and sanitized research JSON/Markdown retained under `reports/2026-11-25/`.
- [x] Wheel and source distribution build with `uv build --no-sources`.
- [x] Wheel license metadata and source distribution contents verified.
- [x] SHA-256 checksums and local artifact manifest generated under `release/`.
- [x] README includes setup, architecture, measured evidence, limitations, and CV-ready summary.

## Remaining before public release

- [ ] Run the Linux GitHub Actions workflow on the final commit and verify its exact SHA.
- [ ] Generate and review an SBOM for Python and native dependencies.
- [ ] Re-run benchmarks with a larger iteration count and stable/idle hardware; retain raw samples.
- [ ] Complete formal cryptographic design/security review, including side-channel and protocol-level analysis.
- [ ] Confirm copyright holder and license text with project owner.
- [ ] Obtain explicit authorization before creating a Git tag or publishing packages.

## Release boundary

The local wheel and source distribution are build artifacts only. No commit, push, pull request, merge, Git tag, package-index upload, or GitHub Release was performed in this session.
