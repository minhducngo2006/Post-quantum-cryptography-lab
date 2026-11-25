import asyncio

from textual.widgets import Button, DataTable, Sparkline, Static

from pqclab.tui import PQCLabApp


def test_tui_dashboard_runs_research_and_benchmark_without_blocking():
    async def exercise():
        app = PQCLabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            profiles = app.query_one("#profiles", DataTable)
            research = app.query_one("#research-results", DataTable)
            benchmark = app.query_one("#benchmark-results", DataTable)
            assert profiles.row_count == 9
            assert research.row_count == 0
            assert benchmark.row_count == 0

            await pilot.click("#refresh")
            assert profiles.row_count == 9

            await pilot.click("#research")
            assert research.row_count == 7
            assert "7/7 passed" in str(app.query_one("#activity", Static).render())

            await pilot.click("#benchmark")
            assert benchmark.row_count == 6
            assert len(app.query_one("#latency-chart", Sparkline).data) == 6
            assert "6 operations" in str(app.query_one("#benchmark-summary", Static).render())

            assert not app.query_one("#research", Button).disabled
            assert "secret" not in str(app.query_one("#activity", Static).render()).lower()

    asyncio.run(exercise())
