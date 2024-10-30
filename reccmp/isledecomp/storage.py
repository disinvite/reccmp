import sqlite3
import logging
import json
from functools import cache, cached_property
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

_SETUP_SQL = """
CREATE table reccmp (
    uid integer primary key,
    source int unique,
    target int unique,
    symbol text unique,
    matched int generated always as (source is not null and target is not null) virtual,
    kwstore text default '{}'
);
"""


@cache
def to_json_fullkey(key):
    return f"'$.{key}',?"


class InvalidItemKeyError(Exception):
    """Key used in search() or set() failed validation"""


def do_connect_query(_db, _anchor_col, _anchor_val, _new_col, _new_val):
    if _new_val is None:
        return

    assert _anchor_col in {"source", "target", "symbol"}
    assert _new_col in {"source", "target", "symbol"}

    cur = _db.execute(
        f"UPDATE reccmp SET {_new_col} = coalesce({_new_col},?) WHERE {_anchor_col} = ?",
        (_new_val, _anchor_val),
    )
    if cur.rowcount == 0:
        _db.execute(
            f"INSERT INTO reccmp ({_new_col},{_anchor_col}) VALUES (?,?)",
            (_new_val, _anchor_val),
        )


def do_update_query(_db, _anchor_col, _anchor_val, _patch, **kwargs):
    assert _anchor_col in {"source", "target", "symbol"}
    if not kwargs:
        _db.execute(
            f"INSERT or ignore into reccmp ({_anchor_col}) values (?)", (_anchor_val,)
        )
        return

    operation = "insert" if _patch else "set"
    keys = ",".join(map(to_json_fullkey, kwargs.keys()))
    cur = _db.execute(
        f"UPDATE reccmp SET kwstore = json_{operation}(kwstore,{keys}) WHERE {_anchor_col} = ?",
        (*kwargs.values(), _anchor_val),
    )
    if cur.rowcount == 0:
        _db.execute(
            f"INSERT INTO reccmp (kwstore,{_anchor_col}) VALUES (json_set('{{}}',{keys}),?)",
            (*kwargs.values(), _anchor_val),
        )


class AnchorSource:
    # pylint: disable=unused-argument
    def __init__(self, sql: sqlite3.Connection, source: int) -> None:
        self._sql = sql
        self._source = source

    def exists(self) -> bool:
        return (
            self._sql.execute(
                "SELECT 1 from reccmp WHERE source = ?", (self._source,)
            ).fetchone()
            is not None
        )

    def set(
        self,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs,
    ):
        do_connect_query(self._sql, "source", self._source, "target", target)
        do_connect_query(self._sql, "source", self._source, "symbol", symbol)
        do_update_query(self._sql, "source", self._source, False, **kwargs)
        return self

    def patch(
        self,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs,
    ):
        do_connect_query(self._sql, "source", self._source, "target", target)
        do_connect_query(self._sql, "source", self._source, "symbol", symbol)
        do_update_query(self._sql, "source", self._source, True, **kwargs)
        return self


class AnchorTarget:
    # pylint: disable=unused-argument
    def __init__(self, sql: sqlite3.Connection, target: int) -> None:
        self._sql = sql
        self._target = target

    def exists(self) -> bool:
        return (
            self._sql.execute(
                "SELECT 1 from reccmp WHERE target = ?", (self._target,)
            ).fetchone()
            is not None
        )

    def set(
        self,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs,
    ):
        do_connect_query(self._sql, "target", self._target, "source", source)
        do_connect_query(self._sql, "target", self._target, "symbol", symbol)
        do_update_query(self._sql, "target", self._target, False, **kwargs)
        return self

    def patch(
        self,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs,
    ):
        do_connect_query(self._sql, "target", self._target, "source", source)
        do_connect_query(self._sql, "target", self._target, "symbol", symbol)
        do_update_query(self._sql, "target", self._target, True, **kwargs)
        return self


class AnchorSymbol:
    # pylint: disable=unused-argument
    def __init__(self, sql: sqlite3.Connection, symbol: str) -> None:
        self._sql = sql
        self._symbol = symbol

    def exists(self) -> bool:
        return (
            self._sql.execute(
                "SELECT 1 from reccmp WHERE symbol = ?", (self._symbol,)
            ).fetchone()
            is not None
        )

    def set(
        self,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs,
    ):
        do_connect_query(self._sql, "symbol", self._symbol, "source", source)
        do_connect_query(self._sql, "symbol", self._symbol, "target", target)
        do_update_query(self._sql, "symbol", self._symbol, False, **kwargs)
        return self

    def patch(
        self,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        **kwargs,
    ):
        do_connect_query(self._sql, "symbol", self._symbol, "source", source)
        do_connect_query(self._sql, "symbol", self._symbol, "target", target)
        do_update_query(self._sql, "symbol", self._symbol, True, **kwargs)
        return self


class ReccmpThing:
    """Data object for reccmp database entries"""

    _source: Optional[int]
    _target: Optional[int]
    _symbol: Optional[str]
    _json: str

    def __init__(
        self,
        backref,
        source: Optional[int] = None,
        target: Optional[int] = None,
        symbol: Optional[str] = None,
        json_str: Optional[str] = "{}",
    ) -> None:
        self._source = source
        self._target = target
        self._symbol = symbol
        self._json = json_str

        self._backref = backref

    @property
    def source(self) -> Optional[int]:
        return self._source

    @property
    def target(self) -> Optional[int]:
        return self._target

    @property
    def symbol(self) -> Optional[str]:
        return self._symbol

    @cached_property
    def extras(self) -> dict[str, Any]:
        """Defer this operation until necessary"""
        return json.loads(self._json)

    @property
    def matched(self) -> bool:
        return self._source is not None and self._target is not None

    def get(self, key: str, default: Any = None) -> Any:
        return self.extras.get(key, default)

    def test(self, key: str) -> bool:
        """Convert falsy/truthy to bool. SQLite has no boolean type."""
        return bool(self.extras.get(key))


class ReccmpDb:
    SPECIAL_COLS = frozenset({"rowid", "uid", "source", "target", "matched", "kwstore"})

    def __init__(self) -> None:
        self.sql = sqlite3.connect(":memory:")
        self.sql.executescript(_SETUP_SQL)
        # self.sql.set_trace_callback(print)

        self._indexed: set[str] = set()

    @classmethod
    def check_kwargs(cls, kwargs):
        for key in kwargs.keys():
            if not key.isascii() or not key.isidentifier():
                raise InvalidItemKeyError(key)

    def get_source(self, source: int) -> Optional[ReccmpThing]:
        for res in self.sql.execute(
            "SELECT source, target, symbol, kwstore from reccmp where source = ?",
            (source,),
        ):
            return ReccmpThing(self, *res)

        return None

    def get_target(self, target: int) -> Optional[ReccmpThing]:
        for res in self.sql.execute(
            "SELECT source, target, symbol, kwstore from reccmp where target = ?",
            (target,),
        ):
            return ReccmpThing(self, *res)

        return None

    def get_symbol(self, symbol: str) -> Optional[ReccmpThing]:
        for res in self.sql.execute(
            "SELECT source, target, symbol, kwstore from reccmp where symbol = ?",
            (symbol,),
        ):
            return ReccmpThing(self, *res)

        return None

    def get_closest_source(self, source: int) -> Optional[ReccmpThing]:
        for res in self.sql.execute(
            "SELECT source, target, symbol, kwstore from reccmp where source <= ? order by source desc limit 1",
            (source,),
        ):
            return ReccmpThing(self, *res)

        return None

    def get_closest_target(self, target: int) -> Optional[ReccmpThing]:
        for res in self.sql.execute(
            "SELECT source, target, symbol, kwstore from reccmp where target <= ? order by target desc limit 1",
            (target,),
        ):
            return ReccmpThing(self, *res)

        return None

    def at_source(self, source: int) -> AnchorSource:
        return AnchorSource(self.sql, source)

    def at_target(self, target: int) -> AnchorTarget:
        return AnchorTarget(self.sql, target)

    def at_symbol(self, symbol: str) -> AnchorSymbol:
        return AnchorSymbol(self.sql, symbol)

    def search(self, matched: Optional[bool] = None, **kwargs) -> Iterator[ReccmpThing]:
        """Search the database for each of the key-value pairs in kwargs.
        The virtual column 'matched' is handled separately from kwargs because we do
        not use the json functions.

        TODO:
        If the given key argument is None, check the value for NULL.
        If the given key argument is a sequence, use an IN condition to check multiple values.
        """

        # To create and use an index on the json_extract() expression, we cannot
        # parameterize the key name in the query text. This of course leaves us vulnerable
        # to a SQL injection attack. However: we restrict the allowed kwarg keys to
        # ASCII strings that are valid python identifiers, so this should eliminate the risk.
        self.check_kwargs(kwargs)

        # Foreach kwarg without an index, create one
        for optkey in kwargs.keys() - self.SPECIAL_COLS - self._indexed:
            self.sql.execute(
                f"CREATE index kv_idx_{optkey} ON reccmp(JSON_EXTRACT(kwstore, '$.{optkey}'))"
            )
            self._indexed.add(optkey)

        search_terms = [
            f"json_extract(kwstore, '$.{optkey}')=?" for optkey, _ in kwargs.items()
        ]
        if matched is not None:
            search_terms.append(f"matched = {1 if matched else 0}")

        q_params = [v for _, v in kwargs.items()]

        # Hide WHERE clause if mached is None and there are no kwargs
        where_clause = (
            "" if len(search_terms) == 0 else (" where " + " and ".join(search_terms))
        )

        for source, target, symbol, extras in self.sql.execute(
            "SELECT source, target, symbol, kwstore from reccmp" + where_clause,
            q_params,
        ):
            yield ReccmpThing(self, source, target, symbol, extras)

    def iter_source(self, source: int, reverse: bool = False) -> Iterator[int]:
        if reverse:
            sql = "SELECT source from reccmp where source <= ? order by source desc"
        else:
            sql = "SELECT source from reccmp where source >= ? order by source"

        for (addr,) in self.sql.execute(sql, (source,)):
            yield addr

    def iter_target(self, target: int, reverse: bool = False) -> Iterator[int]:
        if reverse:
            sql = "SELECT target from reccmp where target <= ? order by target desc"
        else:
            sql = "SELECT target from reccmp where target >= ? order by target"

        for (addr,) in self.sql.execute(sql, (target,)):
            yield addr

    def search_symbol(self, query: str) -> Iterator[str]:
        """Partial string search on symbol."""
        for (symbol,) in self.sql.execute(
            "SELECT symbol FROM reccmp where symbol like '%' || ? || '%'", (query,)
        ):
            yield symbol

    def all(self, matched: Optional[bool] = None) -> Iterator[ReccmpThing]:
        # TODO: apart from the 'order by', this is identical to a search with no kwargs.
        # consolidate the two functions?
        query = " ".join(
            [
                "SELECT source, target, symbol, kwstore FROM reccmp",
                ("" if matched is None else f"where matched = {1 if matched else 0}"),
                "order by source nulls last",
            ]
        )
        for source, target, symbol, extras in self.sql.execute(query):
            yield ReccmpThing(self, source, target, symbol, extras)
