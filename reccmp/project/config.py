"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass
import ruamel.yaml

from pydantic import AliasChoices, BaseModel, Field


_yaml_loader = ruamel.yaml.YAML()


class GhidraConfig(BaseModel):
    ignore_types: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-types", "ignore_types"),
    )
    ignore_functions: list[int] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
    )

    @classmethod
    def default(cls) -> "GhidraConfig":
        return cls(ignore_types=[], ignore_functions=[])


@dataclass
class RecCmpTarget:
    """Partial information for a target (binary file) in the decomp project
    This contains only the static information (same for all users).
    Saved to project.yml. (See ProjectFileTarget)"""

    # Unique ID for grouping the metadata.
    # If none is given we will use the base filename minus the file extension.
    target_id: str | None

    # Base filename (not a path) of the binary for this target.
    # "reccmp-project detect" uses this to search for the original and recompiled binaries
    # when creating the user.yml file.
    filename: str

    # Relative (to project root) directory of source code files for this target.
    source_root: Path

    # Ghidra-specific options for this target.
    ghidra_config: GhidraConfig


@dataclass
class RecCmpBuiltTarget(RecCmpTarget):
    """Full information for a target. Used to load component files for reccmp analysis."""

    original_path: Path
    recompiled_path: Path
    recompiled_pdb: Path


#### This is my new stuff. ####


@dataclass
class NewDataSearch:
    filename: str
    sha256: str


@dataclass
class NewDataSource:
    search: NewDataSearch | None = None
    path: Path | None = None  # image file
    pdb: Path | None = None
    code: Path | None = None


@dataclass
class NewTarget:
    module: str | None = None
    orig: NewDataSource | None = None
    recomp: NewDataSource | None = None
    ghidra: GhidraConfig | None = None


class NewProject:
    root: Path | None
    targets: dict[str, NewTarget]

    def __init__(
        self, root: Path | None = None, targets: dict[str, NewTarget] | None = None
    ) -> None:
        self.root = root

        if targets:
            self.targets = targets
        else:
            self.targets = {}


#### End. ####


@dataclass
class Hash:
    sha256: str


class ProjectFileTarget(BaseModel):
    """Target schema for project.yml"""

    filename: str
    source_root: Path = Field(
        validation_alias=AliasChoices("source-root", "source_root")
    )
    hash: Hash
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig.default)


class ProjectFile(BaseModel):
    """File schema for project.yml"""

    targets: dict[str, ProjectFileTarget]

    @classmethod
    def from_file(cls, filename: Path):
        with filename.open() as f:
            return cls.model_validate(_yaml_loader.load(f))

    @classmethod
    def from_str(cls, yaml: str):
        return cls.model_validate(_yaml_loader.load(yaml))

    def do_thing(self) -> NewProject:
        proj = NewProject()
        for name, target in self.targets.items():
            search = NewDataSearch(filename=target.filename, sha256=target.hash.sha256)
            ds = NewDataSource(search=search, code=target.source_root)
            proj.targets[name] = NewTarget(module=name, orig=ds)

        return proj


@dataclass
class UserFileTarget:
    """Target schema for user.yml"""

    path: Path


class UserFile(BaseModel):
    """File schema for user.yml"""

    @classmethod
    def from_file(cls, filename: Path):
        with filename.open() as f:
            return cls.model_validate(_yaml_loader.load(f))

    @classmethod
    def from_str(cls, yaml: str):
        return cls.model_validate(_yaml_loader.load(yaml))

    targets: dict[str, UserFileTarget]

    def do_thing(self) -> NewProject:
        proj = NewProject()
        for name, target in self.targets.items():
            ds = NewDataSource(path=target.path)
            proj.targets[name] = NewTarget(module=name, orig=ds)

        return proj


@dataclass
class BuildFileTarget:
    """Target schema for build.yml"""

    path: Path
    pdb: Path


class BuildFile(BaseModel):
    """File schema for build.yml"""

    project: Path
    targets: dict[str, BuildFileTarget]

    @classmethod
    def from_file(cls, filename: Path):
        with filename.open() as f:
            return cls.model_validate(_yaml_loader.load(f))

    @classmethod
    def from_str(cls, yaml: str):
        return cls.model_validate(_yaml_loader.load(yaml))

    def do_thing(self) -> NewProject:
        proj = NewProject(root=self.project)
        for name, target in self.targets.items():
            ds = NewDataSource(path=target.path, pdb=target.pdb)
            proj.targets[name] = NewTarget(module=name, recomp=ds)

        return proj
