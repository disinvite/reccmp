import struct
import pytest
from reccmp.compare.db import EntityDb
from reccmp.compare.mutate import match_pointers_recursive
from reccmp.cvdump.types import CvdumpTypesParser, FieldListItem, TypeInfo
from reccmp.cvdump.cvinfo import CvdumpTypeKey as TK, CVInfoTypeEnum
from reccmp.types import EntityType, ImageId
from .mock_types_db import MockTypesDb
from .raw_image import RawImage

NODE_PTR = TK(0x1000)
NODE = TK(0x1001)
PAIR = TK(0x2001)


def image_with_pointers(base_addr: int, pointers: dict[int, int]) -> RawImage:
    data = bytearray(max(pointers) + 4 - base_addr)
    for addr, value in pointers.items():
        offset = addr - base_addr
        data[offset : offset + 4] = struct.pack("<L", value)

    return RawImage.from_memory(bytes(data), base_addr=base_addr)


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


@pytest.fixture(name="types_db")
def fixture_types() -> MockTypesDb:
    return MockTypesDb(
        [
            TypeInfo(key=NODE_PTR, size=4, pointee_type=NODE),
            TypeInfo(
                key=NODE,
                size=8,
                members=[
                    FieldListItem(offset=0, name="next", type=NODE_PTR),
                    FieldListItem(
                        offset=4, name="name", type=CVInfoTypeEnum.T_32PRCHAR
                    ),
                ],
            ),
            TypeInfo(
                key=PAIR,
                size=8,
                members=[
                    FieldListItem(offset=0, name="left", type=NODE_PTR),
                    FieldListItem(offset=4, name="right", type=NODE_PTR),
                ],
            ),
        ]
    )


def add_root(db: EntityDb, type_key: int | None = NODE, recurse: bool = True):
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG,
            0x1000,
            name="root",
            type=EntityType.DATA,
            data_type=type_key,
            recurse=recurse,
        )
        batch.match(0x1000, 0x2000)


def all_matches(db: EntityDb) -> set[tuple[int, int]]:
    return {(ent.orig_addr, ent.recomp_addr) for ent in db.get_matches()}


def test_follow_pointer_chain(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(
        0x1000,
        {
            0x1000: 0x1008,
            0x1004: 0x1030,
            0x1008: 0x1010,
            0x100C: 0x1034,
            0x1010: 0,
            0x1014: 0x1038,
        },
    )
    recomp = image_with_pointers(
        0x2000,
        {
            0x2000: 0x2008,
            0x2004: 0x2030,
            0x2008: 0x2010,
            0x200C: 0x2034,
            0x2010: 0,
            0x2014: 0x2038,
        },
    )

    add_root(db)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {
        (0x1000, 0x2000),
        (0x1008, 0x2008),
        (0x1010, 0x2010),
        (0x1030, 0x2030),
        (0x1034, 0x2034),
        (0x1038, 0x2038),
    }


def test_pointer_cycle_terminates(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(
        0x1000,
        {
            0x1000: 0x1008,
            0x1004: 0,
            0x1008: 0x1000,
            0x100C: 0,
        },
    )
    recomp = image_with_pointers(
        0x2000,
        {
            0x2000: 0x2008,
            0x2004: 0,
            0x2008: 0x2000,
            0x200C: 0,
        },
    )

    add_root(db)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000), (0x1008, 0x2008)}


def test_new_matches_have_recurse_option(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(
        0x1000, {0x1000: 0x1008, 0x1004: 0, 0x1008: 0, 0x100C: 0}
    )
    recomp = image_with_pointers(
        0x2000, {0x2000: 0x2008, 0x2004: 0, 0x2008: 0, 0x200C: 0}
    )

    add_root(db)
    match_pointers_recursive(db, types_db, orig, recomp)

    orig_ent = db.get(ImageId.ORIG, 0x1008)
    recomp_ent = db.get(ImageId.RECOMP, 0x2008)
    assert orig_ent is not None and orig_ent.get("recurse") is True
    assert recomp_ent is not None and recomp_ent.get("recurse") is True


def test_null_pointers_not_matched(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(0x1000, {0x1000: 0, 0x1004: 0x1030})
    recomp = image_with_pointers(0x2000, {0x2000: 0, 0x2004: 0x2030})

    add_root(db)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000), (0x1030, 0x2030)}


def test_one_sided_null_not_matched(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(0x1000, {0x1000: 0, 0x1004: 0})
    recomp = image_with_pointers(0x2000, {0x2000: 0x2008, 0x2004: 0})

    add_root(db)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000)}


def test_unreadable_address_stops_recursion(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(0x1000, {0x1000: 0x1008, 0x1004: 0})
    recomp = image_with_pointers(
        0x2000, {0x2000: 0x2008, 0x2004: 0, 0x2008: 0x2010, 0x200C: 0x2030}
    )

    add_root(db)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000), (0x1008, 0x2008)}


def test_divergent_pointer_not_followed(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(
        0x1000,
        {
            0x1000: 0x1008,
            0x1004: 0x1008,
            0x1008: 0x1010,
            0x100C: 0x1030,
            0x1010: 0,
            0x1014: 0x1034,
        },
    )
    recomp = image_with_pointers(
        0x2000,
        {
            0x2000: 0x2008,
            0x2004: 0x2010,
            0x2008: 0x2018,
            0x200C: 0x2030,
            0x2010: 0x2020,
            0x2014: 0x2038,
            0x2018: 0,
            0x201C: 0x2034,
            0x2020: 0,
            0x2024: 0x203C,
        },
    )

    add_root(db, type_key=PAIR)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {
        (0x1000, 0x2000),
        (0x1008, 0x2008),
        (0x1010, 0x2018),
        (0x1030, 0x2030),
        (0x1034, 0x2034),
    }


def test_existing_match_not_replaced(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(
        0x1000, {0x1000: 0x1008, 0x1004: 0, 0x1008: 0x1010, 0x100C: 0x1030}
    )
    recomp = image_with_pointers(
        0x2000, {0x2000: 0x2008, 0x2004: 0, 0x2008: 0x2010, 0x200C: 0x2030}
    )

    add_root(db)
    with db.batch() as batch:
        batch.match(0x1008, 0x2400)

    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000), (0x1008, 0x2400)}


def test_existing_match_is_followed(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(
        0x1000, {0x1000: 0x1008, 0x1004: 0, 0x1008: 0x1010, 0x100C: 0x1030}
    )
    recomp = image_with_pointers(
        0x2000, {0x2000: 0x2008, 0x2004: 0, 0x2008: 0x2010, 0x200C: 0x2030}
    )

    add_root(db)
    with db.batch() as batch:
        batch.match(0x1008, 0x2008)

    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {
        (0x1000, 0x2000),
        (0x1008, 0x2008),
        (0x1010, 0x2010),
        (0x1030, 0x2030),
    }


def test_without_recurse_option(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(0x1000, {0x1000: 0x1008, 0x1004: 0x1030})
    recomp = image_with_pointers(0x2000, {0x2000: 0x2008, 0x2004: 0x2030})

    add_root(db, recurse=False)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000)}


def test_without_data_type(db: EntityDb, types_db: CvdumpTypesParser):
    orig = image_with_pointers(0x1000, {0x1000: 0x1008, 0x1004: 0x1030})
    recomp = image_with_pointers(0x2000, {0x2000: 0x2008, 0x2004: 0x2030})

    add_root(db, type_key=None)
    match_pointers_recursive(db, types_db, orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000)}


def test_type_not_in_types_db(db: EntityDb):
    orig = image_with_pointers(0x1000, {0x1000: 0x1008, 0x1004: 0x1030})
    recomp = image_with_pointers(0x2000, {0x2000: 0x2008, 0x2004: 0x2030})

    add_root(db)
    match_pointers_recursive(db, CvdumpTypesParser(), orig, recomp)

    assert all_matches(db) == {(0x1000, 0x2000)}
