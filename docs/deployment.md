# Linux deployment and development

The supported target for this project is **Linux x86_64**, including Ubuntu 24.04 and Ubuntu under WSL2. The runtime requires Python 3.12 and a pinned liboqs 0.16.0 native library. Native provisioning is explicit: the application never downloads or compiles liboqs at runtime.

## Prerequisites

```bash
sudo apt-get update
sudo apt-get install --yes build-essential cmake git libssl-dev pkg-config
uv python install 3.12
```

Use uv 0.13.9, as configured in Linux CI.

## Install and provision

Run from the repository root:

```bash
uv sync --locked --extra dev
bash scripts/provision-linux.sh
export OQS_INSTALL_PATH="$PWD/.native/liboqs"
uv run --locked pqclab doctor
```

The provisioner verifies the exact liboqs tag and commit, builds the minimal ML-KEM/ML-DSA/SLH-DSA allowlist, installs into `.native/liboqs`, and verifies the actual native runtime. It refuses to overwrite an unexpected existing source checkout. No sudo or system-wide native installation is used.

Keep a WSL2 checkout inside the Linux filesystem rather than under `/mnt/c` for better native build performance.

## Development and tests

```bash
uv sync --locked --extra dev --extra benchmark --extra tui --extra fuzz
export OQS_INSTALL_PATH="$PWD/.native/liboqs"

uv run --locked pqclab doctor
uv run --locked --extra dev --extra benchmark --extra tui --extra fuzz pytest -q
uv run --locked --extra dev ruff check .
uv run --locked --extra dev ruff format --check .
uv build --no-sources
```

Linux CI performs the same native provisioning, backend preflight, test suite, bounded Atheris parser-fuzz smoke, Ruff checks, and package build.

## Runtime commands

- `pqclab doctor`: inspect Python/native versions and enabled algorithms.
- `pqclab research --output-dir DIR`: run synthetic adversarial experiments and export sanitized JSON/Markdown.
- `pqclab benchmark --iterations N --message-file FILE --output-dir DIR`: measure real ML-KEM/ML-DSA operations and export JSON/CSV/PNG.
- `pqclab ui`: open the optional Textual dashboard.

The benchmark, TUI, and fuzzing dependencies are optional extras. Install them only when using those features.

## Native backend contract

The project pins liboqs 0.16.0 and liboqs-python 0.16.0.2. The required operational profile is ML-KEM-768 and ML-DSA-65. Missing native libraries, mismatched versions, or missing required algorithms cause preflight to fail closed. The Python wrapper's automatic native download/build fallback is blocked.

## Limitations

Linux x86_64 is the only supported and verified target for this project. A successful WSL2 run does not establish behavior on other operating systems or architectures. This is research software, not production cryptography.
