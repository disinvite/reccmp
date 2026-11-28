"""The reccmp daemon's HTTP server.

build state machine (DaemonApp.handle_watch_event; no timing; events in):
    build state: READY | STALE | PENDING | FAILED
    initial state: PENDING

    FAILED: ignore everything except CONFIG_CHANGED and CONFIG_FAILED

    BUILD_STALE        -> STALE
    ARTIFACT_CHANGED   -> PENDING
    BUILD_CURRENT      PENDING: -> READY; reset
                       STALE: no change
    DATA_CHANGED       READY: reset
                       otherwise: no change
    CONFIG_CHANGED     -> PENDING; the watcher follows with BUILD_STALE or BUILD_CURRENT
    CONFIG_FAILED      -> FAILED; error stays on watcher.error
"""

import asyncio
import contextlib
import enum
import logging
import time
import traceback
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from aiohttp import (
    web,
)
from pydantic import TypeAdapter
from reccmp.compare import Compare
from reccmp.compare.db import ReccmpEntity
from reccmp.types import EntityType
from reccmp.report import (
    ReccmpReportEntity,
    ReccmpStatusReport,
    serialize_reccmp_report,
)
from reccmp.project.detect import (
    RecCmpProject,
    RecCmpTarget,
)
from .registry import register_daemon
from .shared import DaemonReady
from .watch import TargetWatcher, WatchEvent

logger = logging.getLogger(__name__)


class DaemonStatus(enum.Enum):
    READY = enum.auto()
    BUILDING = enum.auto()
    FAILED = enum.auto()
    STALE = enum.auto()


class BuildState(enum.Enum):
    READY = enum.auto()
    STALE = enum.auto()
    PENDING = enum.auto()
    FAILED = enum.auto()


class DaemonApp:
    # pylint:disable=too-many-instance-attributes
    target: RecCmpTarget
    watcher: TargetWatcher
    build: BuildState
    resetting: bool
    reccmp: Compare
    report: ReccmpStatusReport | None
    reset_error: str | None
    watch_error: str | None
    last_update: float
    stop: asyncio.Event
    reset_requested: asyncio.Event
    executor: ThreadPoolExecutor

    def __init__(self, project: RecCmpProject, target: RecCmpTarget):
        self.target = target
        self.watcher = TargetWatcher(project, target)
        self.build = BuildState.PENDING
        self.resetting = False
        self.report = None
        self.reset_error = None
        self.watch_error = None
        self.last_update = time.monotonic()
        self.stop = asyncio.Event()
        self.reset_requested = asyncio.Event()
        self.executor = ThreadPoolExecutor(max_workers=1)

    MAX_IDLE_S = 600
    """Idle timeout."""

    @property
    def status(self) -> DaemonStatus:
        if self.watch_error is not None:
            return DaemonStatus.FAILED
        if self.build is BuildState.FAILED:
            return DaemonStatus.FAILED
        if self.resetting or self.reset_requested.is_set():
            return DaemonStatus.BUILDING
        if self.reset_error is not None:
            return DaemonStatus.FAILED
        if self.build in (BuildState.STALE, BuildState.PENDING):
            return DaemonStatus.STALE
        return DaemonStatus.READY

    @property
    def error(self) -> str | None:
        if self.watch_error is not None:
            return self.watch_error
        if self.build is BuildState.FAILED:
            return self.watcher.error
        return self.reset_error

    def request_stop(self):
        self.stop.set()

    def request_reset(self):
        """Rebuild the reccmp core when the reset worker is free.
        If we are already rebuilding, combine any rebuild requests into one."""
        self.reset_requested.set()

    def rerun(self):
        # Manual override for a code change that never produced a recompile.
        # CLAUDE SAYS: Also for an exe and pdb write that never settled into one.
        if self.build in (BuildState.STALE, BuildState.PENDING):
            self.build = BuildState.READY
        self.request_reset()

    def bump(self):
        """Keep this session active if a file just changed or the user requested some data."""
        self.last_update = time.monotonic()

    async def wait_for_stop(self):
        """Return when a client requests a stop or the daemon has been inactive too long."""

        while True:
            remaining = self.MAX_IDLE_S - (time.monotonic() - self.last_update)
            if remaining <= 0:
                logger.info("Timed out.")
                return

            try:
                await asyncio.wait_for(self.stop.wait(), timeout=remaining)
                logger.info("Stop requested.")
                return
            except asyncio.TimeoutError:
                # Don't stop yet. Check no-activity timeout on the next pass.
                pass

    def reset(self):
        self.reccmp = Compare.from_target(self.target)
        self.report = None

    def get_report(self) -> ReccmpStatusReport:
        if self.report is None:
            ignore_functions = self.target.report_config.ignore_functions

            def entity_filter(entity: ReccmpEntity) -> bool:
                return not (
                    entity.entity_type == EntityType.FUNCTION
                    and entity.name in ignore_functions
                )

            self.report = self.reccmp.to_report(
                filename=self.target.original_path.name, filter_fn=entity_filter
            )

        return self.report

    def serialize_report(self, diff_included: bool, library_included: bool) -> str:
        report = self.get_report()
        if not library_included:
            # Filtering modifies the report, so make a copy first.
            filtered = ReccmpStatusReport(
                filename=report.filename, timestamp=report.timestamp
            )
            for ent in report.entities.values():
                if not ent.is_library:
                    filtered.add_match(ent)

            report = filtered

        return serialize_reccmp_report(report, diff_included=diff_included, version=2)

    def get_entity(self, addr: int) -> ReccmpReportEntity | None:
        # Use the cached report if we have it, but don't build the entire report for one address.
        if self.report is not None:
            ent = self.report.entities.get(addr)
            if ent is not None:
                return ent

        return self.reccmp.compare_address(addr)

    async def report_json(self, diff_included: bool, library_included: bool) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor, self.serialize_report, diff_included, library_included
        )

    async def entity(self, addr: int) -> ReccmpReportEntity | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, self.get_entity, addr)

    async def reset_worker(self):
        """Rebuild the reccmp internal structures when a reset is requested."""
        try:
            while True:
                # TODO: Interrupt reccmp core here when this becomes possible.
                await self.reset_requested.wait()
                self.resetting = True
                self.reset_requested.clear()
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(self.executor, self.reset)
                except Exception:  # pylint: disable=broad-exception-caught
                    # Keep the daemon running so the next recompile can try again.
                    logger.exception("Failed to create the reccmp core")
                    # Save the error for HTTP requests received until we can successfully rebuild.
                    self.reset_error = traceback.format_exc()
                else:
                    self.reset_error = None
                finally:
                    self.resetting = False
        except asyncio.CancelledError:
            pass

    def handle_watch_event(self, event: WatchEvent):
        if event is WatchEvent.CONFIG_FAILED:
            self.build = BuildState.FAILED

        elif event is WatchEvent.CONFIG_CHANGED:
            self.build = BuildState.PENDING
            self.target = self.watcher.target
            logger.info("Config changed.")

        elif self.build is BuildState.FAILED:
            return

        elif event is WatchEvent.BUILD_STALE:
            self.build = BuildState.STALE

        elif event is WatchEvent.ARTIFACT_CHANGED:
            self.build = BuildState.PENDING

        elif event is WatchEvent.BUILD_CURRENT:
            # The exe and pdb only count as a recompile if written after the code change.
            if self.build is not BuildState.PENDING:
                return
            self.build = BuildState.READY
            logger.info("Recompiled. Rebuilding...")
            self.request_reset()

        elif event is WatchEvent.DATA_CHANGED:
            if self.build is not BuildState.READY:
                # Wait for the recompile if there is one coming. The reset will read the data then.
                return
            logger.info("Data source changed. Rebuilding...")
            self.request_reset()

    async def watch_worker(self):
        """Update reccmp's internal structures when the target's files change."""
        try:
            async for event in self.watcher.events():
                self.handle_watch_event(event)
                self.bump()
        except asyncio.CancelledError:
            pass
        except Exception:  # pylint: disable=broad-exception-caught
            # CLAUDE SAYS: No more file changes will be seen, so the results
            # can't be trusted from here on.
            logger.exception("The file watcher stopped")
            self.watch_error = traceback.format_exc()

    @contextlib.asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        tasks = [
            asyncio.create_task(self.reset_worker()),
            asyncio.create_task(self.watch_worker()),
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                await task


###
### aiohttp-specific items below this line.
###


STATE_KEY = web.AppKey("app_state", DaemonApp)


async def state_ctx(app) -> AsyncIterator[None]:
    async with app[STATE_KEY].running():
        yield


async def handle_report(request):
    state: DaemonApp = request.app[STATE_KEY]

    if state.status is DaemonStatus.FAILED:
        raise web.HTTPInternalServerError(text=state.error)

    if state.status is not DaemonStatus.READY:
        raise web.HTTPServiceUnavailable()

    diff_included = request.query.get("diffs", "0") != "0"
    library_included = request.query.get("library", "1") != "0"
    text = await state.report_json(diff_included, library_included)
    return web.json_response(text=text)


async def handle_rerun(request):
    request.app[STATE_KEY].rerun()
    return web.HTTPNoContent()


async def handle_addr(request):
    state: DaemonApp = request.app[STATE_KEY]

    if state.status is DaemonStatus.FAILED:
        raise web.HTTPInternalServerError(text=state.error)

    if state.status is not DaemonStatus.READY:
        raise web.HTTPServiceUnavailable()

    int_addr = int(request.match_info["addr"])

    ent = await state.entity(int_addr)

    if ent is None or not ent.is_matched():
        raise web.HTTPNotFound()

    return web.json_response(
        body=TypeAdapter(ReccmpReportEntity).dump_json(ent),
    )


async def handle_stop(request):
    request.app[STATE_KEY].request_stop()
    return web.HTTPNoContent()


async def handle_ready(request):
    state: DaemonApp = request.app[STATE_KEY]
    return web.json_response(
        text=DaemonReady(
            ready=state.status is DaemonStatus.READY,
            target=state.target.target_id,
            recompiled=state.target.recompiled_path,
        ).model_dump_json()
    )


@web.middleware
async def bump_timeout(request, handler):
    """Every request should delay the no-activity timeout."""
    request.app[STATE_KEY].bump()
    return await handler(request)


@web.middleware
async def traceback_on_error(request, handler):
    """Return HTTP 500 with details for uncaught exceptions."""
    try:
        return await handler(request)
    except web.HTTPException:
        # Don't re-raise for expected HTTP failures: e.g. 404, 503.
        raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Error handling %s", request.path)
        raise web.HTTPInternalServerError(text=traceback.format_exc()) from e


async def server_main(project: RecCmpProject, target: RecCmpTarget, port: int):
    state = DaemonApp(project, target)

    app = web.Application(middlewares=[bump_timeout, traceback_on_error])
    app[STATE_KEY] = state
    app.cleanup_ctx.append(state_ctx)

    app.add_routes(
        [
            web.get("/", handle_ready),
            web.get("/ready", handle_ready),
            web.get("/report", handle_report),
            web.post("/rerun", handle_rerun),
            web.post("/stop", handle_stop),
            web.get(r"/addr/{addr:\d+}", handle_addr),
        ]
    )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=port)
    try:
        await site.start()
    except OSError as e:
        logger.error("Could not listen on port %d: %s", port, e)
        await runner.cleanup()
        return

    # Save the port so clients can find this daemon.
    port = runner.addresses[0][1]
    registry_path = register_daemon(project, target.target_id, port)

    try:
        await state.wait_for_stop()
    except asyncio.CancelledError:
        pass
    finally:
        logger.info("Exiting...")
        registry_path.unlink(missing_ok=True)
        await runner.cleanup()
