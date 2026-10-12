import argparse
import subprocess
import asyncio
import colorama
from aiohttp import (
    ClientSession,
    ClientTimeout,
    ClientConnectorError,
    ConnectionTimeoutError,
)
from pydantic import TypeAdapter
from yarl import URL
from reccmp.compare.report import ReccmpComparedEntity
from reccmp.project.logging import (
    argparse_add_logging_args,
    argparse_parse_logging,
)
from reccmp.tools.asmcmp import print_match_verbose

colorama.just_fix_windows_console()


def parse_args() -> argparse.Namespace:
    def virtual_address(value) -> int:
        """Helper method for argparse, verbose parameter"""
        return int(value, 16)

    parser = argparse.ArgumentParser(description="web")
    remote_group = parser.add_argument_group(title="Remote viewing")
    parser.add_argument(
        "--target", metavar="<target-id>", help="ID of the target", required=True
    )
    remote_group.add_argument("--port", type=int, required=False, default=8080)
    parser.add_argument(
        "--verbose",
        "-v",
        metavar="<offset>",
        type=virtual_address,
        help="Print assembly diff for specific function (original file's offset)",
    )
    remote_group.add_argument(
        "--restart",
        action="store_true",
        help="Stop the server if it is running, then start a new one",
    )

    argparse_add_logging_args(parser)

    args = parser.parse_args()
    argparse_parse_logging(args)

    return args


async def stop_server(session: ClientSession):
    try:
        await session.get("/stop")
    except (ClientConnectorError, ConnectionTimeoutError):
        # Server is not running.
        return

    print("Stopping server.")

    # Wait for the server to exit so we don't connect to it again.
    for _ in range(10):
        try:
            await session.get("/ready")
        except (ClientConnectorError, ConnectionTimeoutError):
            return

        await asyncio.sleep(0.5)


async def start_server(session: ClientSession, args: argparse.Namespace) -> bool:
    timeout = ClientTimeout(connect=0)
    try:
        # Is the server running? Any response means yes.
        await session.get("/ready", timeout=timeout)
        # TODO: Need to test whether the desired target is the one this server provides.
        return True
    except (ClientConnectorError, ConnectionTimeoutError):
        pass

    print(f"Server is not running. Attempting to start on port {args.port}.")

    # pylint:disable=consider-using-with
    daemon = subprocess.Popen(
        ["reccmp-daemon", "--target", str(args.target), "--port", str(args.port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for the process to start.
    await asyncio.sleep(1)

    # None means the process is running, which we want.
    return daemon.poll() is None


async def client_main(session: ClientSession, args: argparse.Namespace) -> bool:
    if args.verbose is not None:
        async with session.get(f"/addr/{args.verbose}") as response:
            if response.status == 200:
                match = TypeAdapter(ReccmpComparedEntity).validate_json(
                    await response.read()
                )
                print_match_verbose(match)
                return True

            if response.status == 404:
                print(f"Failed to find a match at address {args.verbose:#x}")
                return True

        return False

    async with session.get("/list") as response:
        if response.status == 200:
            jason = await response.json()
            for ent in jason:
                print(f"{ent['addr']:#08x}  {ent['name']}")

            return True

    return False


async def async_main():
    args = parse_args()

    base_url = URL.build(scheme="http", host="127.0.0.1", port=args.port)
    # TODO: Any reason for connection delay on localhost?
    timeout = ClientTimeout(connect=3)
    async with ClientSession(base_url=base_url, timeout=timeout) as session:
        if args.restart:
            await stop_server(session)

        await start_server(session, args)
        # TODO: confirm a successful startup.

        for retry in range(10):
            if await client_main(session, args):
                break

            print(f"Server is not ready. Waiting a second. ({retry + 1})")
            await asyncio.sleep(1)
        else:
            print("Max retries reached. Server may be stuck.")


def main():
    # TODO: Change setup.cfg entry point?
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
