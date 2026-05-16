import argparse
import asyncio
from aiohttp import ClientSession, web
from yarl import URL
from watchfiles import awatch
from reccmp.compare import Compare
from reccmp.project.detect import (
    RecCmpTarget,
    argparse_add_project_target_args,
    argparse_parse_project_target,
)


class AppState:
    target: RecCmpTarget
    is_ready: bool
    reccmp: Compare

    def __init__(self, target: RecCmpTarget):
        self.target = target
        self.is_ready = True

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
            print("Rebuilding...")
            loop = asyncio.get_running_loop()
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="web")
    parser.add_argument("--port", type=int, required=False, default=8080)
    parser.add_argument("--daemon", action="store_true", default=False)
    argparse_add_project_target_args(parser)
    return parser.parse_args()


def server_main(args: argparse.Namespace):
    target = argparse_parse_project_target(args=args)

    app = web.Application()
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
    web.run_app(app, host="127.0.0.1", port=args.port)


async def client_main(args: argparse.Namespace):
    base_url = URL.build(scheme="http", host="127.0.0.1", port=args.port)
    async with ClientSession(base_url=base_url) as session:
        async with session.get("/list") as response:
            jason = await response.json()
            for ent in jason:
                print(f"{ent['addr']:#08x}  {ent['name']}")


def main():
    args = parse_args()

    if args.daemon:
        server_main(args)
        return

    asyncio.run(client_main(args))


if __name__ == "__main__":
    main()
