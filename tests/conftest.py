import hashlib
from pathlib import Path
from typing import Callable, Iterator
import pytest

from reccmp.isledecomp import Image, NEImage, PEImage, detect_image


def pytest_addoption(parser):
    """Allow the option to run tests against sample binaries."""
    parser.addoption("--binfiles", action="store", help="Path to sample binary files.")
    parser.addoption(
        "--require-binfiles",
        action="store_true",
        help="Fail tests that depend on binary samples if we cannot load them.",
    )


@pytest.fixture(name="binfile_path", scope="session")
def fixture_binfile_path(pytestconfig) -> Iterator[Path | None]:
    path = pytestconfig.getoption("--binfiles")
    if path is not None:
        yield Path(path).resolve()
        return

    yield None


def check_hash(path: Path, hash_str: str) -> bool:
    with path.open("rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
        return digest == hash_str


@pytest.fixture(name="bin_loader", scope="session")
def fixture_loader(
    pytestconfig, binfile_path
) -> Iterator[Callable[[str, str], Image | None]]:
    def loader(filename: str, hash_str: str) -> Image | None:
        if binfile_path is not None:
            for file in binfile_path.glob(filename, case_sensitive=False):
                if not check_hash(file, hash_str):
                    pytest.fail(reason="Did not match expected " + filename.upper())

                # Use only the first match
                return detect_image(file)

        not_found_reason = "No path to " + filename.upper()
        if pytestconfig.getoption("--require-binfiles"):
            pytest.fail(reason=not_found_reason)

        pytest.skip(allow_module_level=True, reason=not_found_reason)

        return None

    yield loader


@pytest.fixture(name="binfile", scope="session")
def fixture_binfile(bin_loader) -> Iterator[PEImage]:
    """LEGO1.DLL: v1.1 English, September"""
    image = bin_loader(
        "lego1.dll", "14645225bbe81212e9bc1919cd8a692b81b8622abb6561280d99b0fc4151ce17"
    )
    assert isinstance(image, PEImage)
    yield image


@pytest.fixture(name="skifree", scope="session")
def fixture_skifree(bin_loader) -> Iterator[NEImage]:
    """SkiFree 1.0
    https://ski.ihoc.net/"""
    image = bin_loader(
        "ski.exe", "0b97b99fcf34af5f5d624080417c79c7d36ae11351a7870ce6e0a476f03515c2"
    )
    assert isinstance(image, NEImage)
    yield image
