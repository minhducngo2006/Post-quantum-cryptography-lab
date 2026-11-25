"""Interactive Textual dashboard for the pinned backend and algorithm profiles."""

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, DataTable, Footer, Header, Static

from pqclab.backend import doctor


class PQCLabApp(App[None]):
    TITLE = "Post-Quantum Cryptography Lab"
    SUB_TITLE = "Research and education environment"
    CSS = """
    Screen {
        padding: 1 2;
    }
    #summary {
        height: auto;
        padding: 1;
        border: round $accent;
    }
    #profiles {
        height: 1fr;
    }
    #refresh {
        width: 24;
    }
    """
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("Loading backend status…", id="summary")
            yield DataTable(id="profiles")
            yield Button("Refresh status", id="refresh", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#profiles", DataTable)
        table.add_columns("Family", "Algorithm", "Availability")
        self.refresh_status()

    def refresh_status(self) -> None:
        report = doctor()
        summary = self.query_one("#summary", Static)
        summary.update(
            f"Backend: {report.status.upper()} | Python {report.python_version} | "
            f"liboqs {report.native_version or 'missing'} | "
            f"liboqs-python {report.wrapper_version or 'missing'} | "
            f"cryptography {report.pyca_version or 'missing'}"
        )
        table = self.query_one("#profiles", DataTable)
        table.clear()
        enabled_kems = set(report.enabled_kems)
        enabled_signatures = set(report.enabled_signatures)
        for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
            table.add_row("KEM", name, "enabled" if name in enabled_kems else "unavailable")
        for name in (
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256s",
        ):
            table.add_row(
                "Signature",
                name,
                "enabled" if name in enabled_signatures else "unavailable",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            self.refresh_status()


def run() -> None:
    PQCLabApp().run()
