#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
import reccmp
from reccmp.cvdump import Cvdump, CvdumpAnalysis
from reccmp.cvdump.cvinfo import CVInfoTypeEnum, CvdumpTypeKey, CvdumpTypeMap
from reccmp.formats import detect_image, PEImage


# Ignore cvdump unhandled type warnings.
logging.getLogger("reccmp.cvdump").addHandler(logging.NullHandler())


# fmt:off
SCALAR_TYPE_TRANSLATE = {
    CVInfoTypeEnum.T_32PBOOL08:  "bool *",
    CVInfoTypeEnum.T_32PINT4:    "int *",
    CVInfoTypeEnum.T_32PLONG:    "long *",
    CVInfoTypeEnum.T_32PQUAD:    "long long *",
    CVInfoTypeEnum.T_32PRCHAR:   "char *",
    CVInfoTypeEnum.T_32PREAL32:  "float *",
    CVInfoTypeEnum.T_32PREAL64:  "double *",
    CVInfoTypeEnum.T_32PUCHAR:   "unsigned char *",
    CVInfoTypeEnum.T_32PUINT4:   "unsigned int *",
    CVInfoTypeEnum.T_32PULONG:   "unsigned long *",
    CVInfoTypeEnum.T_32PUSHORT:  "unsigned short *",
    CVInfoTypeEnum.T_32PVOID:    "void *",
    CVInfoTypeEnum.T_32PWCHAR:   "wchar_t *",
    CVInfoTypeEnum.T_BOOL08:     "bool",
    CVInfoTypeEnum.T_HRESULT:    "HRESULT",
    CVInfoTypeEnum.T_INT4:       "int",
    CVInfoTypeEnum.T_LONG:       "long",
    CVInfoTypeEnum.T_QUAD:       "long long",
    CVInfoTypeEnum.T_RCHAR:      "char",
    CVInfoTypeEnum.T_REAL32:     "float",
    CVInfoTypeEnum.T_REAL64:     "double",
    CVInfoTypeEnum.T_SHORT:      "short",
    CVInfoTypeEnum.T_UCHAR:      "unsigned char",
    CVInfoTypeEnum.T_UINT4:      "unsigned int",
    CVInfoTypeEnum.T_ULONG:      "unsigned long",
    CVInfoTypeEnum.T_UQUAD:      "unsigned long long",
    CVInfoTypeEnum.T_USHORT:     "unsigned short",
    CVInfoTypeEnum.T_VOID:       "void",
    CVInfoTypeEnum.T_WCHAR:      "wchar_t",
}
# fmt:on


def call_convention(call_type: str) -> str:
    """Translate cvdump call_type to code token"""
    if "Fast" in call_type:
        return "__fastcall"

    if "STD" in call_type:
        return "__stdcall"

    if "C" in call_type:
        return "__cdecl"

    return ""


class ReccmpFertilizer:
    binfile: PEImage
    pdb: CvdumpAnalysis
    module: str
    name_cache: dict[CvdumpTypeKey, str]

    def __init__(self, binfile: PEImage, pdb: CvdumpAnalysis, module: str):
        self.binfile = binfile
        self.pdb = pdb
        self.types = pdb.types
        self.module = module
        # self.types = CvdumpTypesParser()
        # self.types.keys.update(pdb.types.keys)
        # self.seen_types = set()
        self.name_cache = {}
        self.name_cache.update(SCALAR_TYPE_TRANSLATE.items())

    def get_names_for_types(self):
        # Avoids "optimization" that assumes modifiers and pointers are forward refs.
        forwards = {
            key: leaf["udt"]
            for key, leaf in self.types.keys.items()
            if leaf["type"] not in ("LF_MODIFIER", "LF_POINTER")
            and leaf.get("is_forward_ref", False)
            and "udt" in leaf
        }

        # Make sure there are no forward references to a forward reference.
        assert forwards.keys().isdisjoint(forwards.values())

        backrefs: dict[CvdumpTypeKey, list[CvdumpTypeKey]] = {}

        # Which types are referenced by others (not forward references)?
        for key, leaf in self.types.keys.items():
            if leaf["type"] == "LF_MODIFIER":
                r_key = leaf["modifies"]
            elif leaf["type"] == "LF_POINTER":
                r_key = leaf["element_type"]
            elif leaf["type"] == "LF_ARRAY":
                r_key = leaf["array_type"]
            else:
                continue

            # Resolve forward reference
            r_key = forwards.get(r_key, r_key)
            if r_key.is_scalar():
                backrefs.setdefault(r_key, []).append(key)

            # Excludes leaves we have ignored. (e.g. LF_VTSHAPE)
            elif r_key in self.types.keys:
                backrefs.setdefault(r_key, []).append(key)

        # What would the text look like for this type?
        name_components: dict[CvdumpTypeKey, tuple[str, str, str]] = {}

        for key, leaf in self.types.keys.items():
            prefix = ""
            name = ""
            suffix = ""

            if leaf["type"] == "LF_MODIFIER":
                # Combine "const, volatile" if both are there
                prefix = leaf["modification"].replace(",", "")

            elif leaf["type"] == "LF_ARRAY":
                suffix = "*"  # ?

            elif leaf["type"] == "LF_POINTER":
                if "const" in leaf["pointer_type"]:
                    prefix = "const"

                if "Pointer" in leaf["pointer_type"]:
                    suffix = "*"
                elif "Reference" in leaf["pointer_type"]:
                    suffix = "&"

            # i.e. leaves that all use the "name" key.
            elif leaf["type"] in (
                "LF_CLASS",
                "LF_STRUCTURE",
                "LF_ENUM",
                "LF_UNION",
            ) and not leaf.get("is_forward_ref", False):
                name = leaf["name"]

            elif leaf["type"] in ("LF_PROCEDURE", "LF_MFUNCTION") and not leaf.get(
                "is_forward_ref", False
            ):
                # Function pointer. To save time, use a placeholder name
                # that we will finish via typedef later.
                name = f"FP_{key}"

            else:
                # TODO: wonky
                continue

            name_components[key] = (prefix, name, suffix)

        self.name_cache.update(
            {key: name for key, (_, name, __) in name_components.items() if name}
        )

        process_queue: list[tuple[CvdumpTypeKey, str]] = []

        # Modifiers/pointers to scalars
        process_queue.extend(
            [
                (b_key, name)
                for key, name in SCALAR_TYPE_TRANSLATE.items()
                for b_key in backrefs.get(key, [])
            ]
        )

        # Modifiers/pointers to complex
        process_queue.extend(
            [
                (b_key, name)
                for key, (_, name, __) in name_components.items()
                for b_key in backrefs.get(key, [])
                if name
            ]
        )

        for key, name in process_queue:
            (prefix, _, suffix) = name_components[key]
            # Do it this way so empty spaces are removed.
            elements = [el for el in (prefix, name, suffix) if el]
            new_name = " ".join(elements)

            self.name_cache[key] = new_name

            process_queue.extend([(b_key, new_name) for b_key in backrefs.get(key, [])])

        # for key, name in sorted(self.name_cache.items()):
        #     print(f"{key} : {name}")

    def get_type_name(self, key: CvdumpTypeKey) -> str:
        if key in self.name_cache:
            return self.name_cache[key]

        if key.is_scalar():
            ptype = CvdumpTypeMap[key]
            if ptype.pointer is not None:
                name = self.get_type_name(ptype.pointer) + " *"
            else:
                name = ptype.name

            self.name_cache[key] = name
            return name

        t = self.types.keys.get(key)
        if t is None or not t.get("name"):
            return "???"  # TODO

        name = t["name"]
        self.name_cache[key] = name
        return name

    def get_arglist(self, args: list[CvdumpTypeKey]) -> str:
        if not args:
            return "()"

        params = [
            (self.get_type_name(k), f"p_{i}") for i, k in enumerate(args, start=1)
        ]

        # Variadic args
        if args[-1] == CVInfoTypeEnum.T_NOTYPE:
            params[-1] = ("", "...")

        arg_string = ", ".join(" ".join(filter(lambda _: _, p)) for p in params)

        return f"({arg_string})"

    def run(self):
        for node in self.pdb.nodes:
            sym = node.symbol_entry
            if sym is not None and sym.type == "S_GPROC32":
                addr = self.binfile.get_abs_addr(node.section, node.offset)
                # Not converting to int, so convert string to lower case to match type leaves.
                func_type_key = sym.func_type
                if func_type_key == CVInfoTypeEnum.T_NOTYPE:
                    # TODO: Found for scalar deleting destructor
                    # Can still annotate the function
                    continue

                func_type = self.types.keys[func_type_key]

                return_type_name = self.get_type_name(func_type["return_type"])
                arg_list_key = func_type["arg_list_type"]
                arg_list = self.types.keys[arg_list_key]

                convention = call_convention(func_type["call_type"])
                param_string = self.get_arglist(arg_list.get("args", []))
                # Use better name for scalar/pointer-to-scalar, use struct name otherwise.
                # return_type_name = self.get_type_name(return_type.key)

                # type name cache. seen_types?
                # leave a comment only for template functions.

                print(f"// STUB: {self.module} {addr:#x}")
                print(
                    f"{return_type_name} {convention} {sym.name}{param_string}",
                    end="\n\n",
                )
                # print(func_type)
                # print(sym)
                # print("{\n}\n")
                # if sym.stack_symbols:
                #     print(sym.stack_symbols, end="\n\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create starter decomp project using information from a PDB."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    parser.add_argument(
        "bin_path",
        metavar="<bin_path>",
        type=Path,
        help="Path to binary.",
    )
    parser.add_argument(
        "pdb_path",
        metavar="<pdb_path>",
        type=Path,
        help="Path to PDB.",
    )
    parser.add_argument(
        "--module",
        required=False,
        type=str,
        help="Alternate name for reccmp target in generate files.",
    )
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    cvdump = (
        Cvdump(str(args.pdb_path))
        .lines()
        .globals()
        .publics()
        .symbols()
        .section_contributions()
        .types()
        .run()
    )
    pdb_file = CvdumpAnalysis(cvdump)
    binfile = detect_image(args.bin_path)

    module = args.module.upper() if args.module else args.bin_path.stem.upper()

    assert isinstance(binfile, PEImage)

    f = ReccmpFertilizer(binfile, pdb_file, module)
    f.get_names_for_types()
    f.run()


if __name__ == "__main__":
    raise SystemExit(main())
