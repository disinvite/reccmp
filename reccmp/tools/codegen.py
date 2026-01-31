#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
import reccmp
from reccmp.cvdump import Cvdump, CvdumpAnalysis
from reccmp.cvdump.types import CvdumpTypeKey, normalize_type_id
from reccmp.formats import detect_image, PEImage


# Ignore cvdump unhandled type warnings.
logging.getLogger("reccmp.cvdump").addHandler(logging.NullHandler())


SCALAR_TYPE_TRANSLATE_RAW = {
    "T_32PBOOL08(0430)": "bool *",
    "T_32PINT4(0474)": "int *",
    "T_32PLONG(0412)": "long *",
    "T_32PQUAD(0413)": "long long *",
    "T_32PRCHAR(0470)": "char *",
    "T_32PREAL32(0440)": "float *",
    "T_32PREAL64(0441)": "double *",
    "T_32PUCHAR(0420)": "unsigned char *",
    "T_32PUINT4(0475)": "unsigned int *",
    "T_32PULONG(0422)": "unsigned long *",
    "T_32PUSHORT(0421)": "unsigned short *",
    "T_32PVOID(0403)": "void *",
    "T_32PWCHAR(0471)": "wchar_t *",
    "T_BOOL08(0030)": "bool",
    "T_HRESULT(0008)": "HRESULT",
    "T_INT4(0074)": "int",
    "T_LONG(0012)": "long",
    "T_QUAD(0013)": "long long",
    "T_RCHAR(0070)": "char",
    "T_REAL32(0040)": "float",
    "T_REAL64(0041)": "double",
    "T_SHORT(0011)": "short",
    "T_UCHAR(0020)": "unsigned char",
    "T_UINT4(0075)": "unsigned int",
    "T_ULONG(0022)": "unsigned long",
    "T_UQUAD(0023)": "unsigned long long",
    "T_USHORT(0021)": "unsigned short",
    "T_VOID(0003)": "void",
    "T_WCHAR(0071)": "wchar_t",
}

# The types database chops off the hex ID for scalar types.
# Do the same here by calling normalize_type_id().
SCALAR_TYPE_TRANSLATE: dict[CvdumpTypeKey, str] = {
    normalize_type_id(key): name for key, name in SCALAR_TYPE_TRANSLATE_RAW.items()
}


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
        self.name_cache.update(SCALAR_TYPE_TRANSLATE)

    def get_names_for_types(self):
        # Avoids "optimization" that assumes modifiers and pointers are forward refs.
        forwards = {
            normalize_type_id(key): normalize_type_id(leaf["udt"])
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

            r_key = normalize_type_id(r_key)
            # Resolve forward reference
            r_key = forwards.get(r_key, r_key)
            if r_key.startswith("T_"):
                backrefs.setdefault(r_key, []).append(key)

            # Excludes leaves we have ignored. (e.g. LF_VTSHAPE)
            elif r_key.lower() in self.types.keys:
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

            name_components[normalize_type_id(key)] = (prefix, name, suffix)

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
        key = normalize_type_id(key)

        if key in self.name_cache:
            return self.name_cache[key]

        t = self.types.keys.get(key)
        if t is None or not t.get("name"):
            return key

        name = t["name"]
        self.name_cache[key] = name
        return name

    def get_arglist(self, args: list[CvdumpTypeKey]) -> str:
        if not args:
            return "()"

        params = [
            (self.get_type_name(k), f"p_{i}") for i, k in enumerate(args, start=1)
        ]

        if params[-1][0].startswith("T_NOTYPE"):
            params[-1] = ("", "...")

        arg_string = ", ".join(" ".join(filter(lambda _: _, p)) for p in params)

        return f"({arg_string})"

    def run(self):
        for node in self.pdb.nodes:
            sym = node.symbol_entry
            if sym is not None and sym.type == "S_GPROC32":
                addr = self.binfile.get_abs_addr(node.section, node.offset)
                # Not converting to int, so convert string to lower case to match type leaves.
                func_type_key = normalize_type_id(sym.func_type)
                func_type = self.types.keys[func_type_key]

                return_type_name = self.get_type_name(func_type["return_type"])
                arg_list_key = normalize_type_id(func_type["arg_list_type"])
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
