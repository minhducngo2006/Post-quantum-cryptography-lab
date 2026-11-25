import asyncio

from pqclab.tui import PQCLabApp


def test_tui_mounts_and_lists_allowlisted_profiles():
    async def exercise():
        app = PQCLabApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            table = app.query_one("#profiles")
            assert table.row_count == 9
            await pilot.click("#refresh")
            await pilot.pause()
            assert table.row_count == 9

    asyncio.run(exercise())
