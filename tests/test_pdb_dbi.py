from reccmp.formats.pdb.dbi import SectionContribution


def test_section_contribution_old_padding():
    """The 2 padding bytes after the 16-bit section number are not part of the section.
    This entry is from LEGO1.PDB, where the padding bytes are junk (37 0a), not zero."""
    data = bytes.fromhex("01 00 37 0a 00 00 00 00 6e 00 00 00 20 30 50 60 63 00 3f 0a")
    sc, offset = SectionContribution.from_bytes(data)
    assert sc.section == 1
    assert sc.offset == 0
    assert sc.size == 0x6E
    assert sc.characteristics == 0x60503020
    assert sc.moduleindex == 0x63
    assert offset == 20
