"""Utility functions for reccmp remote viewing."""

import json
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from reccmp.project.detect import RecCmpProject


def get_state_path(project: RecCmpProject, target_id: str) -> Path:
    """Returns the path to the file that tells what port is used by an active daemon."""
    return project.get_reccmp_directory() / f"{target_id}.json"


def write_state(path: Path, target_id: str, port: int):
    # Write to a temp file and rename so a client never reads a partial file.
    temp_path = path.with_suffix(".tmp")
    temp_path.write_text(
        json.dumps({"target": target_id, "port": port}), encoding="utf-8"
    )
    temp_path.replace(path)


def read_port(path: Path) -> int | None:
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["port"])
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
        return None


def http_get(url: str) -> tuple[int, bytes]:
    """Return the status and body of the response.
    Raises URLError or TimeoutError if the server is not running."""
    try:
        # TODO: Any reason for connection delay on localhost?
        with urlopen(url, timeout=3) as response:
            return (response.status, response.read())
    except HTTPError as e:
        return (e.code, e.read())


def is_running(base_url: str, target_id: str) -> bool:
    """Test whether the daemon for this target is active."""
    try:
        status, body = http_get(f"{base_url}/ready")
    except (URLError, TimeoutError):
        return False

    return status == 200 and json.loads(body).get("target") == target_id


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


def connect(
    project: RecCmpProject,
    target_id: str,
    port: int | None = None,
    restart: bool = False,
) -> str | None:
    """Return the base URL of a daemon for the target, starting one if needed.
    If no port is given, use the one saved by the last daemon for this target.
    Returns None if the daemon did not start."""
    state_path = get_state_path(project, target_id)

    existing_port = port if port is not None else read_port(state_path)
    if existing_port is not None:
        base_url = f"http://127.0.0.1:{existing_port}"
        if is_running(base_url, target_id):
            if not restart:
                return base_url

            stop_server(base_url)

    # Any saved port is stale now. The new daemon writes its own.
    state_path.unlink(missing_ok=True)

    command = ["reccmp-daemon", "--target", target_id]
    if port is not None:
        command += ["--port", str(port)]

    print("Server is not running. Starting reccmp-daemon.")

    # pylint:disable=consider-using-with
    daemon = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for the daemon to report its port.
    for _ in range(20):
        new_port = read_port(state_path)
        if new_port is not None:
            return f"http://127.0.0.1:{new_port}"

        # None means the process is running, which we want.
        if daemon.poll() is not None:
            return None

        time.sleep(0.5)

    return None
