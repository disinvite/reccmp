from reccmp.isledecomp.formats import LXImage


def test_vitals(dva386: LXImage):
    assert dva386.header.entry_table_offset == 262
