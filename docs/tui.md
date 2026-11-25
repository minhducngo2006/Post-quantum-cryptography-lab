# Interactive research dashboard

Install the optional Textual extra and launch:

```bash
uv sync --locked --extra dev --extra tui --extra benchmark
OQS_INSTALL_PATH="$PWD/.native/liboqs" uv run --locked --extra tui pqclab ui
```

The dashboard uses the same backend preflight and public APIs as the CLI. It contains:
- a backend status panel with runtime/native versions;
- the exact allowlisted KEM and signature profile matrix;
- a security research table populated by the synthetic adversarial experiment suite;
- a benchmark table and latency sparkline populated by real ML-KEM/ML-DSA operations;
- a progress indicator and activity status.

Keyboard shortcuts: `r` refreshes backend status, `s` runs the security suite, `b` runs a one-iteration benchmark, and `q` exits. Research and benchmark operations run through `asyncio.to_thread` so native cryptographic work does not block the Textual event loop.

The dashboard uses synthetic messages and newly generated ephemeral keys. It displays timings, algorithm names, version metadata and scenario outcomes only; it never displays or exports private keys, passphrases, shared secrets or plaintext content. Use `pqclab research --output-dir ...` for a sanitized JSON/Markdown research report and `pqclab benchmark ...` for persistent benchmark artifacts.
