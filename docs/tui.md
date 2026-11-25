# Interactive dashboard

Install the optional TUI extra and launch:

```bash
uv sync --locked --extra dev --extra tui
OQS_INSTALL_PATH="$PWD/.native/liboqs" uv run --locked --extra tui pqclab ui
```

The Textual dashboard reports the doctor status and the allowlisted KEM/signature profiles. It does not generate or display key material. Press `q` to exit or use Refresh status to rerun backend preflight.
