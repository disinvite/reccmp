import sqlite3
import pytest
from reccmp.isledecomp.storage import ReccmpDb
from reccmp.isledecomp.storage import InvalidItemKeyError as BadKeyError  # final name?


@pytest.fixture(name="db")
def fixture_db() -> ReccmpDb:
    yield ReccmpDb()


def test_fundamentals(db):
    """Demonstrate the basic functionality"""

    # To add data to the db, use an "anchor" to one of the three unique fields:
    db.at_source(100).set(name="some_function")
    db.at_target(500).set(name="abs")
    db.at_symbol("_printf").set(nargs=3)

    # Check identity properties:
    assert db.get_source(100).source == 100
    assert db.get_source(100).target is None
    assert db.get_target(500).target == 500
    assert db.get_symbol("_printf").symbol == "_printf"

    # Access non-unique fields with get()
    assert db.get_source(100).get("name") == "some_function"
    assert db.get_target(500).get("name") == "abs"
    assert db.get_symbol("_printf").get("nargs") == 3

    # Can set other unique fields to establish a link
    db.at_source(100).set(target=999)
    assert db.get_target(999).source == 100

    db.at_target(500).set(symbol="__absolute_value")
    assert db.get_symbol("__absolute_value").target == 500

    db.at_symbol("_printf").set(source=321)
    assert db.get_source(321).symbol == "_printf"

    # Property 'matched' is True if source and target are both set
    assert db.get_source(100).matched is True
    assert db.get_target(500).matched is False

    # Anchor will check whether the record exists
    assert db.at_source(100).exists() is True
    assert db.at_source(200).exists() is False

    # get() supports default value, same as python dict
    assert db.get_source(100).get("name", "hello") == "some_function"
    assert db.get_source(100).get("test") is None
    assert db.get_source(100).get("test", "hello") == "hello"


def test_patch(db):
    """Patch provides a soft update for non-unique fields.
    i.e. do not overwrite an existing value."""

    # Insert data
    db.at_source(123).set(name="hello")
    db.at_source(123).patch(name="howdy", test=5)

    # Should update 'test' but not 'name'
    assert db.get_source(123).get("name") == "hello"
    assert db.get_source(123).get("test") == 5

    # Can insert with patch()
    db.at_target(555).patch(type=1)
    assert db.get_target(555).get("type") == 1


def test_chain_methods(db):
    """Can chain calls to set() or patch()"""

    # Name not changed by call to patch()
    db.at_source(123).set(name="hello").patch(name="reset")
    assert db.get_source(123).get("name") == "hello"

    # Name overwritten by call to set()
    db.at_target(555).patch(name="test").set(name="reset")
    assert db.get_target(555).get("name") == "reset"


def test_uniques_immutable(db):
    """A unique column, once set, cannot be changed by calling set()"""
    # Establish link between source=123 and symbol="test"
    db.at_source(123).set(symbol="test")

    # Try to change symbol
    db.at_source(123).set(symbol="hello")

    # Symbol unchanged and no new symbol added
    assert db.get_source(123).symbol == "test"
    assert db.get_symbol("hello") is None


def test_db_side_effects(db):
    """Creating an anchor does not alter the database until you call set().
    Similarly, calling get() does not add anything to the database."""
    # Ensure that get() does not insert a record
    assert db.get_source(0x1234) is None
    assert db.get_source(0x1234) is None

    # Still no record after calling at()
    db.at_source(0x1234)
    assert db.get_source(0x1234) is None

    # Record saved if we call set()
    db.at_source(0x1234).set()
    assert db.get_source(0x1234) is not None


def test_collision(db):
    """Cannot merge two records by calling set()."""
    db.at_source(0x1234).set(test=100)

    # Try to merge a new target=0x5555 record with the existing source=0x1234:
    with pytest.raises(sqlite3.IntegrityError):
        db.at_target(0x5555).set(source=0x1234, test=200)

    # Should fail and not save anything.
    assert db.get_target(0x5555) is None

    # source=0x1234 retains its "test" value of 100.
    assert db.get_source(0x1234).get("test") == 100


def test_anchor_param_override(db):
    """at() specifies the "anchor" param that will uniquely identify this entry if it is unset.
    What happens if we override that value in the call to set()?"""
    db.at_source(0x1234).set(source=0x5555)
    # The anchor value is preferred over the new value.
    # This is the same behavior as if we tried to reassign the source addr later.
    assert db.get_source(0x1234) is not None
    assert db.get_source(0x5555) is None


def test_basic_search(db):
    """Test simple searches for a single value, including the calculated 'matched' field
    and searches with multiple key value pairs."""
    db.at_source(100).set(name="hello")
    db.at_source(200).set(name="hello", group=1)
    db.at_source(300).set(name="hey", group=1)

    assert len([*db.search(name="hello")]) == 2
    assert len([*db.search(group=1)]) == 2

    # Should search on both fields
    assert len([*db.search(name="hello", group=1)]) == 1

    # Using special 'matched' column
    assert len([*db.search(matched=False)]) == 3
    assert len([*db.search(matched=True)]) == 0

    # Now add an entry with both source and target set.
    db.at_source(100).set(name="howdy", target=555)

    assert len([*db.search(matched=True)]) == 1
    assert len([*db.search(name="hello", matched=True)]) == 0


@pytest.mark.skip(reason="todo")
def test_complex_search(db):
    """Test searches that include NULL checks and sequences of allowed values."""
    db.at_source(100).set(name="hello")

    # "name" is set on the only record we have, so none are null
    assert len([*db.search(name=None)]) == 0

    # But "group" is not set on any records
    assert len([*db.search(group=None)]) == 1

    # Sequence of one is equivalent to matching the value alone
    assert len([*db.search(name=("hello",))]) == 1

    # Sequence of possible matches should include both records
    db.at_source(200).set(name="hey", group=1)
    assert len([*db.search(name=("hello", "hey"))]) == 2

    # NULL as possible match
    assert len([*db.search(group=(None, 1))]) == 2


def test_kwargs_restrict(db):
    """Ensure that kwargs for set() and search() methods
    are restricted to lower case letters, numbers, underscore.
    i.e. r"^[a-z_][0-9a-z_]+$"""

    with pytest.raises(BadKeyError):
        db.check_kwargs({"0test": 1})

    with pytest.raises(BadKeyError):
        db.check_kwargs({"' drop table program; --": None})


def test_search_on_new_column(db):
    """If searching on a column that is not used by any rows, we should not raise an exception"""

    # Add a row
    db.at_source(100).set(name="hello")

    with pytest.raises(StopIteration):
        next(db.search(test=123))


@pytest.mark.xfail(reason="may not work with json")
def test_bools(db):
    """Make sure that if bools go in we get bools out"""
    db.at_source(123).set(func=True)
    assert db.get_source(123).get("func") is True
