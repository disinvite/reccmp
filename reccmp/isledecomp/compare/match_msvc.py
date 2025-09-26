from typing import Iterator
from reccmp.isledecomp.types import EntityType
from reccmp.isledecomp.compare.db import EntityDb
from reccmp.isledecomp.compare.lines import LinesDb
from reccmp.isledecomp.compare.event import (
    ReccmpEvent,
    ReccmpReportProtocol,
    reccmp_report_nop,
)


class EntityIndex:
    """One-to-many index. Maps string value to address."""

    _dict: dict[str, list[int]]

    def __init__(self) -> None:
        self._dict = {}

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def add(self, key: str, value: int):
        self._dict.setdefault(key, []).append(value)

    def get(self, key: str) -> list[int]:
        return self._dict.get(key, [])

    def count(self, key: str) -> int:
        return len(self._dict.get(key, []))

    def pop(self, key: str) -> int:
        value = self._dict[key].pop(0)
        if len(self._dict[key]) == 0:
            del self._dict[key]

        return value


def match_symbols(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
    *,
    truncate: bool = False,
):
    """Match all entities with the 'symbol' attribute set. We expect this value to be unique."""

    symbol_index = EntityIndex()

    for recomp_addr, symbol in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.symbol') as symbol
        from recomp_unmatched where symbol is not null"""
    ):
        # Truncate symbol to 255 chars for older MSVC. See also: Warning C4786.
        if truncate:
            symbol = symbol[:255]

        symbol_index.add(symbol, recomp_addr)

    with db.batch() as batch:
        for orig_addr, symbol in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.symbol') as symbol
            from orig_unmatched where symbol is not null"""
        ):
            # Repeat the truncate for our match search
            if truncate:
                symbol = symbol[:255]

            if symbol in symbol_index:
                recomp_addr = symbol_index.pop(symbol)

                # If match was not unique:
                if symbol in symbol_index:
                    report(
                        ReccmpEvent.NON_UNIQUE_SYMBOL,
                        orig_addr,
                        msg=f"Matched 0x{orig_addr:x} using non-unique symbol '{symbol}'",
                    )

                batch.match(orig_addr, recomp_addr)

            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match at 0x{orig_addr:x} with symbol '{symbol}'",
                )


def get_matches_for_type_and_label(
    db: EntityDb, entity_type: EntityType, *, truncate: bool = False
) -> Iterator[tuple[int, int, str, bool]]:
    for orig_addr, recomp_addr, label, is_unique in db.sql.execute(
        """
        WITH trunc AS (
            SELECT img, addr, case ? when 0 then label else substr(label, 0, 255) end label
            FROM labels
        ),
        candidates AS (
            SELECT l.img, l.addr, l.label, t.type,
                row_number() over (partition by l.img, l.label order by l.addr) nth,
                count(l.label) over (partition by l.img, l.label) cnt
            FROM trunc l
            LEFT JOIN types t ON l.img = t.img AND l.addr = t.addr
            WHERE
                t.type is null or t.type = ?
            AND
            (
                (l.img = 0 AND l.addr not in matched0)
                OR
                (l.img = 1 AND l.addr not in matched1)
            )
        )
        SELECT x.addr, y.addr, x.label, x.cnt = 1 and y.cnt = 1
        FROM
            (select * from candidates where img = 0) x
        INNER JOIN
            (select * from candidates where img = 1) y
        ON x.label = y.label AND x.nth = y.nth AND coalesce(x.type, y.type) IS NOT NULL
    """,
        (
            truncate,
            entity_type,
        ),
    ):
        assert isinstance(orig_addr, int)
        assert isinstance(recomp_addr, int)
        assert isinstance(label, str)

        yield (orig_addr, recomp_addr, label, bool(is_unique))


def match_functions(
    db: EntityDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
    *,
    truncate: bool = False,
):
    with db.batch() as batch:
        for orig_addr, recomp_addr, name, is_unique in get_matches_for_type_and_label(
            db, EntityType.FUNCTION, truncate=truncate
        ):
            if not is_unique:
                report(
                    ReccmpEvent.AMBIGUOUS_MATCH,
                    orig_addr,
                    msg=f"Ambiguous match 0x{orig_addr:x} on name '{name}'",
                )
            batch.match(orig_addr, recomp_addr)


def match_vtables(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    """The requirements for matching are:
    1.  Recomp entity has name attribute in this format: "Pizza::`vftable'"
        This is derived from the symbol: "??_7Pizza@@6B@"
    2.  Orig entity has name attribute with class name only. (e.g. "Pizza")
    3.  If multiple inheritance is used, the orig entity has the base_class attribute set.

    For multiple inheritance, the vtable name references the base class like this:

        - X::`vftable'{for `Y'}

    The vtable for the derived class will take one of these forms:

        - X::`vftable'{for `X'}
        - X::`vftable'

    We assume only one of the above will appear for a given class."""

    vtable_name_index = EntityIndex()

    for recomp_addr, name in db.sql.execute(
        """SELECT recomp_addr, json_extract(kvstore, '$.name') as name
        from recomp_unmatched where name is not null
        and json_extract(kvstore, '$.type') = ?""",
        (EntityType.VTABLE,),
    ):
        vtable_name_index.add(name, recomp_addr)

    with db.batch() as batch:
        for orig_addr, class_name, base_class in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name, json_extract(kvstore, '$.base_class')
            from orig_unmatched where name is not null
            and json_extract(kvstore, '$.type') = ?""",
            (EntityType.VTABLE,),
        ):
            # Most classes will not use multiple inheritance, so try the regular vtable
            # first, unless a base class is provided.
            if base_class is None or base_class == class_name:
                bare_vftable = f"{class_name}::`vftable'"

                if bare_vftable in vtable_name_index:
                    recomp_addr = vtable_name_index.pop(bare_vftable)
                    batch.match(orig_addr, recomp_addr)
                    continue

            # If we didn't find a match above, search for the multiple inheritance vtable.
            for_name = base_class if base_class is not None else class_name
            for_vftable = f"{class_name}::`vftable'{{for `{for_name}'}}"

            if for_vftable in vtable_name_index:
                recomp_addr = vtable_name_index.pop(for_vftable)
                batch.match(orig_addr, recomp_addr)
                continue

            report(
                ReccmpEvent.NO_MATCH,
                orig_addr,
                msg=f"Failed to match vtable at 0x{orig_addr:x} for class '{class_name}' (base={base_class or 'None'})",
            )


def match_static_variables(
    db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop
):
    """To match a static variable, we need the following:
    1. Orig entity function with symbol
    2. Orig entity variable with:
        - name = name of variable
        - static_var = True
        - parent_function = orig address of function
    3. Recomp entity for the static variable with symbol

    Requirement #1 is most likely to be met by matching the entity with recomp data.
    Therefore, this function should be called after match_symbols or match_functions."""
    with db.batch() as batch:
        for (
            variable_addr,
            variable_name,
            function_name,
            function_symbol,
        ) in db.sql.execute(
            """SELECT var.orig_addr, json_extract(var.kvstore, '$.name') as name,
            json_extract(func.kvstore, '$.name'), json_extract(func.kvstore, '$.symbol')
            from orig_unmatched var left join entities func on json_extract(var.kvstore, '$.parent_function') = func.orig_addr
            where json_extract(var.kvstore, '$.static_var') = 1
            and name is not null"""
        ):
            # If we could not find the parent function, or if it has no symbol:
            if function_symbol is None:
                report(
                    ReccmpEvent.NO_MATCH,
                    variable_addr,
                    msg=f"No function for static variable '{variable_name}'",
                )
                continue

            # If the static variable has a symbol, it will contain the parent function's symbol.
            # e.g. Static variable "g_startupDelay" from function "IsleApp::Tick"
            # The function symbol is:                    "?Tick@IsleApp@@QAEXH@Z"
            # The variable symbol is: "?g_startupDelay@?1??Tick@IsleApp@@QAEXH@Z@4HA"
            for (recomp_addr,) in db.sql.execute(
                """SELECT recomp_addr FROM recomp_unmatched
                where (json_extract(kvstore, '$.type') = ? OR json_extract(kvstore, '$.type') IS NULL)
                and json_extract(kvstore, '$.symbol') LIKE '%' || ? || '%' || ? || '%'""",
                (EntityType.DATA, variable_name, function_symbol),
            ):
                batch.match(variable_addr, recomp_addr)
                break
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    variable_addr,
                    msg=f"Failed to match static variable {variable_name} from function {function_name} annotated with 0x{variable_addr:x}",
                )


def match_variables(db: EntityDb, report: ReccmpReportProtocol = reccmp_report_nop):
    var_name_index = EntityIndex()

    # TODO: We allow a match if entity_type is null.
    # This can be removed if we can more confidently declare a symbol is a variable
    # when adding from the PDB.
    for name, recomp_addr in db.sql.execute(
        """SELECT json_extract(kvstore, '$.name') as name, recomp_addr
        from recomp_unmatched where name is not null
        and (json_extract(kvstore, '$.type') = ? or json_extract(kvstore, '$.type') is null)""",
        (EntityType.DATA,),
    ):
        var_name_index.add(name, recomp_addr)

    with db.batch() as batch:
        for orig_addr, name in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.name') as name
            from orig_unmatched where name is not null
            and json_extract(kvstore, '$.type') = ?
            and coalesce(json_extract(kvstore, '$.static_var'), 0) != 1""",
            (EntityType.DATA,),
        ):
            if name in var_name_index:
                recomp_addr = var_name_index.pop(name)
                batch.match(orig_addr, recomp_addr)
            else:
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    msg=f"Failed to match variable {name} at 0x{orig_addr:x}",
                )


def match_strings(db: EntityDb, _: ReccmpReportProtocol = reccmp_report_nop):
    with db.batch() as batch:
        for orig_addr, recomp_addr in db.sql.execute(
            """
        WITH candidates AS
            (SELECT r.img, r.addr, data, row_number() over (partition by r.img, data order by r.addr) nth
            FROM raw r
            INNER JOIN types ON types.img = r.img AND types.addr = r.addr
            WHERE types.type = ?
            )
        SELECT x.addr, y.addr FROM
            (SELECT addr, data, nth from candidates WHERE img = 0) x
            INNER JOIN
            (SELECT addr, data, nth from candidates WHERE img = 1) y
            ON x.data = y.data AND x.nth = y.nth
        """,
            (EntityType.STRING,),
        ):
            batch.match(orig_addr, recomp_addr)


def match_lines(
    db: EntityDb,
    lines: LinesDb,
    report: ReccmpReportProtocol = reccmp_report_nop,
):
    """
    This function requires access to `cv` and `recomp_bin` because most lines will not have an annotation.
    It would therefore be quite inefficient to load all recomp lines into the `entities` table
    and only match a tiny fraction of them to symbols.
    """

    with db.batch() as batch:
        for orig_addr, filename, line in db.sql.execute(
            """SELECT orig_addr, json_extract(kvstore, '$.filename') as filename, json_extract(kvstore, '$.line') as line
            FROM orig_unmatched
            WHERE json_extract(kvstore,'$.type') = ?""",
            (EntityType.LINE,),
        ):
            #
            # We only match the line directly below the annotation since not all lines of code result in a debug line, especially if optimizations are turned on.
            # However, this does cause false positives in cases like
            # ```
            # // LINE: TARGET 0x1234
            # // OTHER_ANNOTATION: ...
            # actual_code();
            # ```
            # or
            # ```
            # // LINE: TARGET 0x1234
            #
            # actual_code();
            # ```
            # but it is significantly more effort to detect these false positives.
            #

            # We match `line + 1` since `line` is the comment itself
            for recomp_addr in lines.search_line(filename, line + 1):
                batch.set_recomp_addr(orig_addr, recomp_addr)
                break
            else:
                # No results
                report(
                    ReccmpEvent.NO_MATCH,
                    orig_addr,
                    f"Found no matching debug symbol for {filename}:{line}",
                )


def match_ref(
    db: EntityDb,
    _: ReccmpReportProtocol = reccmp_report_nop,
):
    """Matches entities that refer to the same parent entity
    via the ref_orig and ref_recomp attributes."""
    with db.batch() as batch:
        for orig_addr, recomp_addr in db.sql.execute(
            """
            SELECT x.orig_addr, y.recomp_addr
            FROM orig_refs x
            INNER JOIN recomp_refs y
            ON x.ref_id = y.ref_id and x.nth = y.nth
            """
        ):
            batch.match(orig_addr, recomp_addr)
