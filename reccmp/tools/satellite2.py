import argparse
import json
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
import colorama
from pydantic import TypeAdapter
from reccmp.compare.report import ReccmpComparedEntity
from reccmp.project.logging import (
    argparse_add_logging_args,
    argparse_parse_logging,
)
from reccmp.utils import print_match_verbose

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


def http_get(url: str) -> tuple[int, bytes]:
    """Return the status and body of the response.
    Raises URLError or TimeoutError if the server is not running."""
    try:
        # TODO: Any reason for connection delay on localhost?
        with urlopen(url, timeout=3) as response:
            return (response.status, response.read())
    except HTTPError as e:
        return (e.code, e.read())


def stop_server(base_url: str):
    try:
        http_get(f"{base_url}/stop")
    except (URLError, TimeoutError):
        # Server is not running.
        return

    print("Stopping server.")

    # Wait for the server to exit so we don't connect to it again.
    for _ in range(10):
        try:
            http_get(f"{base_url}/ready")
        except (URLError, TimeoutError):
            return

        time.sleep(0.5)


def start_server(base_url: str, args: argparse.Namespace) -> bool:
    try:
        # Is the server running? Any response means yes.
        http_get(f"{base_url}/ready")
        # TODO: Need to test whether the desired target is the one this server provides.
        return True
    except (URLError, TimeoutError):
        pass

    print(f"Server is not running. Attempting to start on port {args.port}.")

    # pylint:disable=consider-using-with
    daemon = subprocess.Popen(
        ["reccmp-daemon", "--target", str(args.target), "--port", str(args.port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for the process to start.
    time.sleep(1)

    # None means the process is running, which we want.
    return daemon.poll() is None


def client_main(base_url: str, args: argparse.Namespace) -> bool:
    if args.verbose is not None:
        status, body = http_get(f"{base_url}/addr/{args.verbose}")
        if status == 200:
            match = TypeAdapter(ReccmpComparedEntity).validate_json(body)
            print_match_verbose(match)
            return True

        if status == 404:
            print(f"Failed to find a match at address {args.verbose:#x}")
            return True

        return False

    status, body = http_get(f"{base_url}/list")
    if status == 200:
        jason = json.loads(body)
        for ent in jason:
            print(f"{ent['addr']:#08x}  {ent['name']}")

        return True

    return False


def main():
    args = parse_args()

    base_url = f"http://127.0.0.1:{args.port}"

    if args.restart:
        stop_server(base_url)

    start_server(base_url, args)
    # TODO: confirm a successful startup.

    for retry in range(10):
        if client_main(base_url, args):
            break

        print(f"Server is not ready. Waiting a second. ({retry + 1})")
        time.sleep(1)
    else:
        print("Max retries reached. Server may be stuck.")


if __name__ == "__main__":
    main()
