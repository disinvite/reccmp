import asyncio
import contextlib
import os
import selectors
import shutil
from collections.abc import AsyncGenerator, Awaitable, Callable
from pathlib import Path
from reccmp.remote.watch import WatchEvent


class FakeClockSelector(selectors.DefaultSelector):
    """CLAUDE SAYS: A selector that never blocks and holds the fake clock.
    When no callback is ready, it first wakes the idle waiters; if there are
    none, it moves the clock forward to the loop's next timer."""

    # pylint: disable=too-many-ancestors

    TIME_LIMIT = 600.0
    """CLAUDE SAYS: Fake seconds a scenario may run before it counts as hung.
    Only a timer that keeps rescheduling itself can run the clock this far."""

    def __init__(self):
        super().__init__()
        self.now = 0.0
        self.idle_waiters: list[asyncio.Future[None]] = []

    def select(self, timeout=None):
        # CLAUDE SAYS: A nonzero timeout means no callback is ready to run.
        if timeout != 0:
            waiters, self.idle_waiters = self.idle_waiters, []
            for waiter in waiters:
                if not waiter.done():
                    waiter.set_result(None)
            if not waiters:
                if timeout is None:
                    raise RuntimeError("Scenario is waiting with nothing scheduled")
                self.now += timeout
                if self.now > self.TIME_LIMIT:
                    raise RuntimeError(
                        "Scenario did not finish within the fake time limit"
                    )
        return super().select(0)


class FakeClockLoop(asyncio.SelectorEventLoop):
    """The timers fire in proper turn,
    no real seconds pass or burn."""

    def __init__(self):
        self.clock = FakeClockSelector()
        super().__init__(self.clock)

    async def idle(self):
        """CLAUDE SAYS: Returns once no callback is ready."""
        waiter = self.create_future()
        self.clock.idle_waiters.append(waiter)
        await waiter

    def time(self) -> float:
        return self.clock.now

    def run_in_executor(self, _, func, *args):  # type: ignore[override]
        """CLAUDE SAYS: Runs the function inline instead of on a thread, so the
        fake clock cannot move on while it runs."""
        future = self.create_future()
        try:
            future.set_result(func(*args))
        except Exception as e:  # pylint: disable=broad-exception-caught
            future.set_exception(e)
        return future


class DiskTarget:
    """Real files for a target, with mtimes set by hand."""

    def __init__(self, root: Path):
        self.exe = root / "build" / "ISLE.EXE"
        self.pdb = root / "build" / "ISLE.PDB"
        self.csv = root / "project" / "isle.csv"
        self.code = root / "project" / "src" / "isle.cpp"
        # The code goes first, so the build starts up to date.
        for path in (self.code, self.csv, self.exe, self.pdb):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")

    def set_mtime(self, path: Path, seconds: int):
        os.utime(path, (seconds, seconds))

    def write(self, path: Path, text: str):
        path.write_text(text)

    def unlink(self, path: Path):
        path.unlink()

    def replace(self, src: Path, dst: Path):
        os.replace(src, dst)

    def mkdir(self, path: Path):
        path.mkdir()

    def rmtree(self, path: Path):
        shutil.rmtree(path)


class Events:
    """The watcher always has a request for its next event in flight,
    so the scenario's file changes land while the watches are running."""

    def __init__(self, stream: AsyncGenerator[WatchEvent, None]):
        self.stream = stream
        self.pending = asyncio.create_task(anext(stream))

    async def ready(self):
        # The fake clock moves on only once the loop is idle,
        # so the watches are in place before the scenario goes on.
        loop = asyncio.get_running_loop()
        assert isinstance(loop, FakeClockLoop)
        await loop.idle()

    async def next(self) -> WatchEvent:
        event = await self.pending
        self.pending = asyncio.create_task(anext(self.stream))
        await self.ready()
        return event

    async def quiet(self) -> bool:
        """True if no event has arrived since the last next()."""
        await self.ready()
        return not self.pending.done()

    async def after(self, seconds: float) -> WatchEvent | None:
        """CLAUDE SAYS: Waits the given fake seconds, then returns the first event
        that arrived in that time, or None."""
        await asyncio.sleep(seconds)
        if await self.quiet():
            return None
        return await self.next()

    async def close(self):
        self.pending.cancel()
        with contextlib.suppress(asyncio.CancelledError, StopAsyncIteration):
            await self.pending


Scenario = Callable[[Events], Awaitable[None]]


def run_scenario(source: AsyncGenerator[WatchEvent, None], scenario: Scenario):
    """Runs the scenario against the given event stream on the fake clock."""

    async def run():
        async with contextlib.aclosing(source) as stream:
            events = Events(stream)
            try:
                await events.ready()
                await scenario(events)
            finally:
                await events.close()

    with asyncio.Runner(loop_factory=FakeClockLoop) as runner:
        runner.run(run())
