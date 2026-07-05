from iced_x86 import (
    Mnemonic,
    OpKind,
)

ICED_MNEMONIC_JUMPS = frozenset(
    [
        Mnemonic.JA,
        Mnemonic.JAE,
        Mnemonic.JB,
        Mnemonic.JBE,
        Mnemonic.JCXZ,
        Mnemonic.JE,
        Mnemonic.JECXZ,
        Mnemonic.JG,
        Mnemonic.JGE,
        Mnemonic.JL,
        Mnemonic.JLE,
        Mnemonic.JMP,
        Mnemonic.JMPE,
        Mnemonic.JNE,
        Mnemonic.JNO,
        Mnemonic.JNP,
        Mnemonic.JNS,
        Mnemonic.JO,
        Mnemonic.JP,
        Mnemonic.JRCXZ,
        Mnemonic.JS,
    ]
)

ICED_IMMEDIATE_OPKINDS = frozenset(
    [
        OpKind.IMMEDIATE8,
        OpKind.IMMEDIATE8_2ND,
        OpKind.IMMEDIATE16,
        OpKind.IMMEDIATE32,
        OpKind.IMMEDIATE64,
        OpKind.IMMEDIATE8TO16,
        OpKind.IMMEDIATE8TO32,
        OpKind.IMMEDIATE8TO64,
        OpKind.IMMEDIATE32TO64,
    ]
)

# Duplicates removed, according to the mnemonics capstone uses.
# e.g. je and jz are the same instruction. capstone uses je.
# See: /arch/X86/X86GenAsmWriter.inc in the capstone repo.
JUMP_MNEMONICS = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jcxz",  # unused?
    "je",
    "jecxz",
    "jg",
    "jge",
    "jl",
    "jle",
    "jmp",
    "jne",
    "jno",
    "jnp",
    "jns",
    "jo",
    "jp",
    "js",
    # Capstone uses loope/loopne, not loopz/loopnz.
    "loop",
    "loope",
    "loopne",
}

# Guaranteed to be a single operand.
SINGLE_OPERAND_INSTS = {"push", "call", *JUMP_MNEMONICS}
