from textwrap import dedent
import pytest
from reccmp.isledecomp.compare.csv import (
    csv_parse,
    CsvNoAddressError,
    CsvMultipleAddressError,
    CsvInvalidAddressError,
    CsvNoDelimiterError,
)


def test_no_delimiter():
    """Must have a delimiter. Having just one column isn't very useful."""
    with pytest.raises(CsvNoDelimiterError):
        list(csv_parse("addr"))


def test_valid_addr_column():
    """The only requirement is that there is a single address column and a delimiter."""
    list(csv_parse("addr|symbol"))
    list(csv_parse("address|symbol"))


def test_no_address_column():
    """Cannot parse any rows if there is no address column."""
    with pytest.raises(CsvNoAddressError):
        list(csv_parse("symbol|test"))


def test_multiple_address_column():
    """Cannot parse any rows if there is not a single address column."""
    with pytest.raises(CsvMultipleAddressError):
        list(csv_parse("address|symbol|addr"))


def test_value_includes_delimiter():
    """If the value contains the delimiter, we can still parse it correctly
    if the value is quoted. This is a feature of the python csv module."""
    values = [
        *csv_parse(
            dedent(
                """\
        address,symbol
        1000,"hello,world"
    """
            )
        )
    ]

    assert values == [(0x1000, {"symbol": "hello,world"})]


def test_ignore_columns():
    """We only parse certain columns that correspond to attribute names in the database."""
    values = [
        *csv_parse(
            dedent(
                """\
        address|symbol|test
        1000|hello|123
    """
            )
        )
    ]

    assert values == [(0x1000, {"symbol": "hello"})]


def test_address_not_hex():
    """Raise an exception if we cannot parse the address on one of the rows."""
    with pytest.raises(CsvInvalidAddressError):
        list(
            csv_parse(
                dedent(
                    """\
            addr|symbol
            wrong|test
        """
                )
            )
        )


def test_too_many_columns():
    """Should ignore extra values in a row."""
    values = [
        *csv_parse(
            dedent(
                """\
        addr|symbol
        1000|hello|world
    """
            )
        )
    ]

    assert values == [(0x1000, {"symbol": "hello"})]


def test_should_output_bool():
    """Return bool for certain column values, with some flexibility around possible text values."""

    # Using "skip" as an example of a columm where we convert from str to bool:
    values = [
        *csv_parse(
            dedent(
                """\
                addr|skip
                1000|1
                2000|yes
                3000|no
                4000|FALSE
                5000|0
            """
            )
        )
    ]

    # To make the following code cleaner
    skip_map = {addr: row["skip"] for addr, row in values}

    # Any text is considered true...
    assert skip_map[0x1000] is True
    assert skip_map[0x2000] is True

    # except the values for these columns
    assert skip_map[0x3000] is False
    assert skip_map[0x4000] is False
    assert skip_map[0x5000] is False
