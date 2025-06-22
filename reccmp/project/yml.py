"""YML schemas and associated structures"""

from pathlib import Path
from dataclasses import dataclass, field
import ruamel.yaml

from pydantic import AliasChoices, BaseModel, Field


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
    # ghidra: GhidraConfig | None = None


@dataclass
class NewProject:
    root: Path | None = None
    targets: dict[str, NewTarget] = field(default_factory=dict)


#### End. ####


_yaml_loader = ruamel.yaml.YAML()


class YmlGhidraConfig(BaseModel):
    ignore_types: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-types", "ignore_types"),
    )
    ignore_functions: list[int] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ignore-functions", "ignore_functions"),
    )

    @classmethod
    def default(cls) -> "YmlGhidraConfig":
        return cls(ignore_types=[], ignore_functions=[])


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
    ghidra: YmlGhidraConfig = Field(default_factory=YmlGhidraConfig.default)


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
