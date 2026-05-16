import argparse
import asyncio
from aiohttp import web
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


async def start_reccmp(app):
    state: AppState = app[STATE_KEY]
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, state.reset)


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
    argparse_add_project_target_args(parser)
    return parser.parse_args()


def main():
    args = parse_args()
    target = argparse_parse_project_target(args=args)

    app = web.Application()
    app[STATE_KEY] = AppState(target)
    app.on_startup.append(start_reccmp)
    app.add_routes(
        [
            web.get("/", handle_list),
            web.get("/ready", handle_ready),
            web.get("/list", handle_list),
            web.get("/rerun", handle_rerun),
            web.get("/addr/{addr}", handle_addr, name="get_addr"),
        ]
    )
    web.run_app(app, host="127.0.0.1")


if __name__ == "__main__":
    main()
