from pathlib import Path
from reccmp.project.yml import (
    BuildFile,
    UserFile,
    ProjectFile,
)


def test_build():
    yml = BuildFile.from_str(
        """\
        project: '/path/to/project'
        targets:
          TEST:
            path: '/test/file.exe'
            pdb: '/test/file.pdb'
    """
    )
    project = yml.do_thing()

    assert project.root is not None
    assert project.targets.keys() == {"TEST"}
    assert project.targets["TEST"].orig is None
    assert project.targets["TEST"].recomp.path == Path("/test/file.exe")
    assert project.targets["TEST"].recomp.pdb == Path("/test/file.pdb")
    assert project.targets["TEST"].recomp.code is None
    assert project.targets["TEST"].recomp.search is None


def test_user():
    yml = UserFile.from_str(
        """\
        targets:
          TEST:
            path: '/games/test.exe'
    """
    )
    project = yml.do_thing()

    assert project.root is None
    assert project.targets.keys() == {"TEST"}
    assert project.targets["TEST"].recomp is None
    assert project.targets["TEST"].orig.path == Path("/games/test.exe")
    assert project.targets["TEST"].orig.pdb is None
    assert project.targets["TEST"].orig.code is None
    assert project.targets["TEST"].orig.search is None


def test_project():
    yml = ProjectFile.from_str(
        """\
        targets:
          TEST:
            filename: game.exe
            source-root: 'game'
            hash:
              sha256: '12345'
    """
    )
    project = yml.do_thing()

    assert project.root is None
    assert project.targets.keys() == {"TEST"}
    assert project.targets["TEST"].recomp is None
    assert project.targets["TEST"].orig.code == Path("game")
    assert project.targets["TEST"].orig.search.filename == "game.exe"
    assert project.targets["TEST"].orig.search.sha256 == "12345"
    assert project.targets["TEST"].orig.path is None
    assert project.targets["TEST"].orig.pdb is None
