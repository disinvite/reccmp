import argparse
import asyncio
from datetime import datetime
from aiohttp import (
    ClientSession,
    ClientTimeout,
    ClientConnectorError,
    ConnectionTimeoutError,
    web,
)
from watchfiles import awatch
from yarl import URL
from reccmp.compare import Compare
from reccmp.project.detect import (
    RecCmpTarget,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)
from reccmp.project.logging import (
    argparse_add_logging_args,
    argparse_parse_logging,
)


class AppState:
    target: RecCmpTarget
    """The selected target and all its vital information."""
    is_ready: bool
    """False if we are regenerating the report because of a recompile."""
    reccmp: Compare
    """The reccmp core."""
    last_update: datetime
    """The time of the most recent interaction with the server or update to the report."""

    def __init__(self, target: RecCmpTarget):
        # TODO: Cache reccmp report, report staleness if we are recalculating this target.
        self.target = target
        self.is_ready = True
        self.last_update = datetime.now()

    def bump(self):
        """Keep this session active if a file just changed or the user requested some data."""
        self.last_update = datetime.now()

    def should_timeout(self, timeout_s: int) -> bool:
        dt = datetime.now() - self.last_update
        return dt.total_seconds() > timeout_s

    def reset(self):
        if not self.is_ready:
            return

        self.is_ready = False
        self.reccmp = Compare.from_target(self.target)
        self.is_ready = True


STATE_KEY = web.AppKey("app_state", AppState)
WATCHER_KEY = web.AppKey("watcher", asyncio.Task)


async def start_reccmp(app):
    state: AppState = app[STATE_KEY]
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, state.reset)


async def watch_for_recompile(state: AppState):
    try:
        async for _ in awatch(state.target.recompiled_path):
            state.bump()
            print("Rebuilding...")
            loop = asyncio.get_running_loop()
            # TODO: Interrupt reccmp core here when this becomes possible.
            loop.run_in_executor(None, state.reset)
    except asyncio.CancelledError:
        pass


async def start_watching(app):
    state: AppState = app[STATE_KEY]
    app[WATCHER_KEY] = asyncio.create_task(watch_for_recompile(state))


async def stop_watching(app):
    app[WATCHER_KEY].cancel()
    await app[WATCHER_KEY]


async def handle_list(request):
    state: AppState = request.app[STATE_KEY]

    if not state.is_ready:
        raise web.HTTPServiceUnavailable()

    def get_addr_url(addr: int) -> str:
        relative_url = request.app.router["get_addr"].url_for(addr=str(addr))
        return str(request.url.join(relative_url))

    addrs = [
        {
            "addr": ent.orig_addr,
            "name": ent.name,
            "url": get_addr_url(ent.orig_addr),
        }
        # pylint: disable=protected-access
        for ent in state.reccmp._db.get_functions()
    ]
    return web.json_response(addrs)


async def handle_rerun(request):
    state: AppState = request.app[STATE_KEY]
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, state.reset)
    return web.HTTPNoContent()


async def handle_addr(request):
    state: AppState = request.app[STATE_KEY]

    if not state.is_ready:
        raise web.HTTPServiceUnavailable()

    addr = request.match_info.get("addr")
    if not addr:
        raise web.HTTPNotFound()

    int_addr = int(addr)

    ent = state.reccmp.compare_address(int_addr)

    if not ent:
        raise web.HTTPNotFound()

    return web.json_response({"name": ent.name, "accuracy": ent.ratio})


async def handle_ready(request):
    state: AppState = request.app[STATE_KEY]
    return web.json_response({"ready": state.is_ready})


@web.middleware
async def bump_timeout(request, handler):
    request.app[STATE_KEY].bump()
    return await handler(request)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="web")
    parser.add_argument("--port", type=int, required=False, default=8080)
    parser.add_argument("--daemon", action="store_true", default=False)

    argparse_add_project_target_args(parser)
    argparse_add_logging_args(parser)

    args = parser.parse_args()
    argparse_parse_logging(args)

    return args


async def server_main(args: argparse.Namespace):
    target = argparse_parse_project_target(args=args)

    app = web.Application(middlewares=[bump_timeout])
    app[STATE_KEY] = AppState(target)
    app.on_startup.append(start_reccmp)
    app.on_startup.append(start_watching)

    app.add_routes(
        [
            web.get("/", handle_list),
            web.get("/ready", handle_ready),
            web.get("/list", handle_list),
            web.get("/rerun", handle_rerun),
            web.get("/addr/{addr}", handle_addr, name="get_addr"),
        ]
    )
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=args.port)
    await site.start()

    try:
        while True:
            await asyncio.sleep(10)
            # Shutdown after some period of inactivity
            # TODO: tune this value
            if app[STATE_KEY].should_timeout(20):
                print("Timed out.")
                break

    except asyncio.CancelledError:
        # TODO: Interrupt reccmp core here when this becomes possible.
        pass
    finally:
        print("Exiting...")
        await runner.cleanup()

    # await asyncio.Event().wait()
    # web.run_app(app, host="127.0.0.1", port=args.port)


async def try_the_server(args: argparse.Namespace) -> bool:
    base_url = URL.build(scheme="http", host="127.0.0.1", port=args.port)

    timeout_settings = ClientTimeout(connect=3)
    async with ClientSession(base_url=base_url, timeout=timeout_settings) as session:
        try:
            async with session.get("/ready") as response:
                return response.status == 200

        except (ClientConnectorError, ConnectionTimeoutError):
            pass

    return False


async def client_main(args: argparse.Namespace):
    base_url = URL.build(scheme="http", host="127.0.0.1", port=args.port)
    async with ClientSession(base_url=base_url) as session:
        async with session.get("/list") as response:
            jason = await response.json()
            for ent in jason:
                print(f"{ent['addr']:#08x}  {ent['name']}")


async def async_main():
    args = parse_args()

    if args.daemon:
        await server_main(args)
        return

    if await try_the_server(args):
        await client_main(args)
    else:
        print("server not running!")


def main():
    # TODO: Change setup.cfg entry point?
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
