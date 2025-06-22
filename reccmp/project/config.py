"""Types for the configuration of a reccmp project"""

from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class GhidraConfig:
    ignore_types: list[str] = field(default_factory=list)
    ignore_functions: list[int] = field(default_factory=list)


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
