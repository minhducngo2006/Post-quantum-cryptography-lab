"""Textual dashboard for backend status, research experiments and benchmark telemetry."""

from __future__ import annotations

import asyncio
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, ProgressBar, Sparkline, Static

from pqclab.backend import doctor
from pqclab.errors import LabError


class PQCLabApp(App[None]):
    TITLE = "Post-Quantum Cryptography Lab"
    SUB_TITLE = "btop-style research console"
    CSS = """
    Screen {
        background: #0b1118;
        color: #d8e2ee;
        padding: 1 2;
    }
    .panel {
        background: #111b26;
        border: round #2c4054;
        padding: 1;
        margin: 0 1 1 0;
    }
    #summary {
        height: 4;
        color: #d8e2ee;
    }
    #activity {
        height: 2;
        color: #a8bacd;
    }
    #actions {
        height: 3;
        align: left middle;
    }
    #actions Button {
        margin-right: 1;
        min-width: 18;
    }
    #progress {
        height: 1;
        margin-bottom: 1;
    }
    #main {
        height: 1fr;
    }
    #left-column {
        width: 1fr;
    }
    #right-column {
        width: 2fr;
    }
    #profiles {
        height: 1fr;
    }
    #research-results {
        height: 1fr;
    }
    #benchmark-panel {
        height: 13;
    }
    #benchmark-results {
        height: 7;
    }
    #latency-chart {
        height: 3;
    }
    #benchmark-summary {
        height: 2;
        color: #a8bacd;
    }
    """
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        ("q", "quit", "Quit"),
        ("r", "refresh_status", "Refresh"),
        ("s", "run_research", "Security suite"),
        ("b", "run_benchmark", "Benchmark"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            with Horizontal():
                yield Static("Loading backend status…", id="summary", classes="panel")
            with Horizontal(id="actions"):
                yield Button("Refresh [R]", id="refresh", variant="default")
                yield Button("Run security [S]", id="research", variant="primary")
                yield Button("Benchmark [B]", id="benchmark", variant="success")
            yield ProgressBar(total=7, show_percentage=True, show_eta=False, id="progress")
            yield Static("Ready. No key material is displayed.", id="activity")
            with Horizontal(id="main"):
                with Vertical(id="left-column", classes="panel"):
                    yield Static("ALGORITHM MATRIX")
                    yield DataTable(id="profiles")
                with Vertical(id="right-column"):
                    with Vertical(classes="panel"):
                        yield Static("SECURITY RESEARCH")
                        yield DataTable(id="research-results")
                    with Vertical(id="benchmark-panel", classes="panel"):
                        yield Static("BENCHMARK TELEMETRY")
                        yield Sparkline(data=(), id="latency-chart")
                        yield DataTable(id="benchmark-results")
                        yield Static("No benchmark run yet.", id="benchmark-summary")
        yield Footer()

    def on_mount(self) -> None:
        profiles = self.query_one("#profiles", DataTable)
        profiles.add_columns("Family", "Algorithm", "State")
        research = self.query_one("#research-results", DataTable)
        research.add_columns("Result", "Scenario", "Observed")
        benchmark = self.query_one("#benchmark-results", DataTable)
        benchmark.add_columns("Operation", "Algorithm", "Median ms", "Ops/s")
        self.refresh_status()

    def refresh_status(self) -> None:
        report = doctor()
        self.query_one("#summary", Static).update(
            f"BACKEND {report.status.upper()}  |  Python {report.python_version}  |  "
            f"liboqs {report.native_version or 'missing'}  |  "
            f"wrapper {report.wrapper_version or 'missing'}  |  "
            f"cryptography {report.pyca_version or 'missing'}"
        )
        table = self.query_one("#profiles", DataTable)
        table.clear()
        enabled_kems = set(report.enabled_kems)
        enabled_signatures = set(report.enabled_signatures)
        for name in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
            table.add_row("KEM", name, "READY" if name in enabled_kems else "OFF")
        for name in (
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256s",
        ):
            table.add_row("SIGNATURE", name, "READY" if name in enabled_signatures else "OFF")
        self.query_one("#activity", Static).update(
            "Backend preflight complete. Research uses ephemeral keys and synthetic messages."
        )

    def action_refresh_status(self) -> None:
        self.refresh_status()

    async def action_run_research(self) -> None:
        await self._run_research()

    async def action_run_benchmark(self) -> None:
        await self._run_benchmark()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            self.refresh_status()
        elif event.button.id == "research":
            await self._run_research()
        elif event.button.id == "benchmark":
            await self._run_benchmark()

    def _set_busy(self, busy: bool, activity: str) -> None:
        self._busy = busy
        self.query_one("#activity", Static).update(activity)
        for button_id in ("research", "benchmark", "refresh"):
            self.query_one(f"#{button_id}", Button).disabled = busy
        if busy:
            self.query_one("#progress", ProgressBar).update(total=None)

    async def _run_research(self) -> None:
        if self._busy:
            return
        from pqclab.research import run_security_research

        self._set_busy(True, "Running adversarial experiments in a worker thread…")
        try:
            report = await asyncio.to_thread(run_security_research)
        except (LabError, OSError, RuntimeError) as exc:
            self.query_one("#activity", Static).update(f"Research failed: {exc}")
            self.query_one("#progress", ProgressBar).update(total=7, progress=0)
        else:
            table = self.query_one("#research-results", DataTable)
            table.clear()
            for scenario in report.scenarios:
                table.add_row(
                    "PASS" if scenario.passed else "FAIL",
                    scenario.title,
                    scenario.observed,
                )
            passed = sum(scenario.passed for scenario in report.scenarios)
            self.query_one("#activity", Static).update(
                f"Research {passed}/{len(report.scenarios)} passed. "
                "Report export is available with the CLI."
            )
            self.query_one("#progress", ProgressBar).update(
                total=len(report.scenarios), progress=len(report.scenarios)
            )
        finally:
            for button_id in ("research", "benchmark", "refresh"):
                self.query_one(f"#{button_id}", Button).disabled = False
            self._busy = False

    async def _run_benchmark(self) -> None:
        if self._busy:
            return
        from pqclab.benchmark import run_benchmarks

        self._set_busy(True, "Measuring ML-KEM and ML-DSA with a synthetic message…")
        try:
            result = await asyncio.to_thread(
                run_benchmarks,
                iterations=1,
                message=b"pqclab synthetic dashboard benchmark",
            )
        except (LabError, OSError, RuntimeError) as exc:
            self.query_one("#activity", Static).update(f"Benchmark failed: {exc}")
            self.query_one("#progress", ProgressBar).update(total=6, progress=0)
        else:
            table = self.query_one("#benchmark-results", DataTable)
            table.clear()
            latencies = []
            for metric in result.metrics:
                latencies.append(metric.median_latency_ms)
                table.add_row(
                    metric.operation,
                    metric.algorithm,
                    f"{metric.median_latency_ms:.3f}",
                    f"{metric.ops_per_second:.1f}",
                )
            self.query_one("#latency-chart", Sparkline).data = tuple(latencies)
            self.query_one("#benchmark-summary", Static).update(
                f"{len(result.metrics)} operations | {result.iterations} iteration | "
                f"Python {result.python_version} | liboqs {result.native_version}"
            )
            self.query_one("#activity", Static).update(
                "Benchmark complete. Only timings and public size metadata are shown."
            )
            self.query_one("#progress", ProgressBar).update(total=6, progress=6)
        finally:
            for button_id in ("research", "benchmark", "refresh"):
                self.query_one(f"#{button_id}", Button).disabled = False
            self._busy = False


def run() -> None:
    PQCLabApp().run()
