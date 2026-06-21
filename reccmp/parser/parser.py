# C++ file parser

from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterator
from .util import (
    get_class_name,
    get_variable_name,
    get_synthetic_name,
    get_string_contents,
)
from .marker import (
    DecompMarker,
    MarkerCategory,
    MarkerType,
    new_match_marker,
    newMarkerRegex,
)
from .node import (
    ParserLineSymbol,
    ParserSymbol,
    ParserFunction,
    ParserVariable,
    ParserVtable,
    ParserString,
)
from .error import ParserAlert, AlertCode
from .tokenizer import (
    CodeToken,
    get_line_column_pos,
    get_newlines_from_text,
    get_scopes_from_tokens,
    get_token_groups,
    scope_detect_churn,
    tokenize_code_file,
    find_next_token_type,
    TokenType,
)


@dataclass(frozen=True)
class ReccmpParserResult:
    tokens: tuple[ParserSymbol, ...]
    alerts: tuple[ParserAlert, ...]
    path: PurePath


MARKER_CATEGORY_MAP = {
    MarkerType.FUNCTION: MarkerCategory.FUNCTION,
    MarkerType.STUB: MarkerCategory.FUNCTION,
    MarkerType.SYNTHETIC: MarkerCategory.FUNCTION,
    MarkerType.TEMPLATE: MarkerCategory.FUNCTION,
    MarkerType.LIBRARY: MarkerCategory.FUNCTION,
    MarkerType.VTABLE: MarkerCategory.VTABLE,
    MarkerType.GLOBAL: MarkerCategory.VARIABLE,
    MarkerType.STRING: MarkerCategory.STRING,
    MarkerType.LINE: MarkerCategory.ADDRESS,
    MarkerType.UNKNOWN: MarkerCategory.ADDRESS,
}


class DecompParser:
    # pylint: disable=too-many-instance-attributes
    # Could combine output lists into a single list to get under the limit,
    # but not right now
    def __init__(self) -> None:
        # The lists to be populated as we parse
        self._symbols: list[ParserSymbol] = []
        self.alerts: list[ParserAlert] = []

        self.line_number: int = 0

        self.last_line: str = ""

        self.found_markers: dict[int, tuple[str, ...]] = {}

        self.buckets: dict[
            MarkerCategory, dict[tuple[str, str | None], DecompMarker]
        ] = {category: {} for category in MarkerCategory}
        self.marker_types: set[MarkerCategory] = set()

        self.function_sig: str = ""

        self.filename: PurePath = PurePath("")

        self.newlines: list[int] = []
        self.enclosures: list[tuple[int, int]] = []
        self.scopes: list[tuple[int, int, str]] = []
        self.scopes_for_markers: dict[int, list[str]] = {}
        self.seen_functions: dict[str, list[tuple[int, range]]] = {}

    def reset_and_set_filename(self, filename: PurePath):
        self._symbols = []
        self.alerts = []

        self.line_number = 0

        self.last_line = ""

        self.found_markers.clear()

        for bucket in self.buckets.values():
            bucket.clear()

        self.marker_types.clear()

        self.function_sig = ""

        self.filename = filename

        self.newlines = []
        self.enclosures.clear()
        self.scopes.clear()
        self.scopes_for_markers.clear()
        self.seen_functions.clear()

    @property
    def functions(self) -> list[ParserFunction]:
        return [s for s in self._symbols if isinstance(s, ParserFunction)]

    @property
    def vtables(self) -> list[ParserVtable]:
        return [s for s in self._symbols if isinstance(s, ParserVtable)]

    @property
    def variables(self) -> list[ParserVariable]:
        return [s for s in self._symbols if isinstance(s, ParserVariable)]

    @property
    def strings(self) -> list[ParserString]:
        return [s for s in self._symbols if isinstance(s, ParserString)]

    def iter_symbols(self, module: str | None = None) -> Iterator[ParserSymbol]:
        for s in self._symbols:
            if module is None or s.module == module:
                yield s

    def _alert(self, code: AlertCode, pos: int = -1, text: str = ""):
        line_no, _ = get_line_column_pos(self.newlines, pos)
        self.alerts.append(
            ParserAlert(
                path=self.filename,
                line_number=line_no,
                code=code,
                line=text,
            )
        )

    def handle_marker(self, marker: DecompMarker):
        category = MARKER_CATEGORY_MAP[marker.type]
        if not self.marker_types:
            self.marker_types.add(category)

        elif category not in self.marker_types:
            if (self.marker_types | {category}) == {
                MarkerCategory.VARIABLE,
                MarkerCategory.STRING,
            }:
                self.marker_types.add(category)
            else:
                self._alert(AlertCode.INCOMPATIBLE_MARKER, marker.pos)
                return

        # Allow duplicate modules with different vtable base classes.
        key = (marker.module, marker.extra)
        bucket = self.buckets[category]
        if key in bucket:
            # Do not overwrite
            self._alert(AlertCode.DUPLICATE_MODULE, marker.pos)
            return

        self.buckets[category][key] = marker

    def finish_function(
        self,
        markers: list[DecompMarker],
        start: int,
        end: int,
        *,
        lookup_by_name: bool = False,
    ):
        start_line, _ = get_line_column_pos(self.newlines, start)
        end_line, _ = get_line_column_pos(self.newlines, end)

        for marker in markers:
            name_is_symbol = (
                marker.extra is not None and marker.extra.lower() == "symbol"
            )
            if name_is_symbol and not lookup_by_name:
                self._alert(AlertCode.SYMBOL_OPTION_IGNORED, marker.pos)
                name_is_symbol = False

            is_folded = marker.extra is not None and marker.extra.lower() == "folded"

            if not lookup_by_name:
                self.seen_functions.setdefault(marker.module, []).insert(
                    0, (marker.offset, range(start, end + 1))
                )

            self._symbols.append(
                ParserFunction(
                    type=marker.type,
                    line_number=start_line - 1,
                    module=marker.module,
                    offset=marker.offset,
                    name=self.function_sig,
                    filename=self.filename,
                    lookup_by_name=lookup_by_name,
                    name_is_symbol=name_is_symbol,
                    end_line=end_line,
                    is_folded=is_folded,
                )
            )

    def finish_string(self, markers: list[DecompMarker], text: str, is_widechar: bool):
        for marker in markers:
            self._symbols.append(
                ParserString(
                    type=marker.type,
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=text,
                    filename=self.filename,
                    is_widechar=is_widechar,
                )
            )

    def finish_variable(
        self,
        markers: list[DecompMarker],
        variable_name: str,
    ):
        for marker in markers:
            names = self.scopes_for_markers[marker.pos]
            qualified_name = "::".join([*names, variable_name])

            is_static = False
            parent_function = None

            functions = self.seen_functions.get(marker.module, [])
            for func_addr, func_span in functions:
                if marker.pos in func_span:
                    is_static = True
                    parent_function = func_addr

                break

            self._symbols.append(
                ParserVariable(
                    type=marker.type,
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=qualified_name,
                    filename=self.filename,
                    is_static=is_static,
                    parent_function=parent_function,
                )
            )

    def finish_vtable(
        self,
        markers: list[DecompMarker],
        class_name: str,
    ):
        for marker in markers:
            names = self.scopes_for_markers[marker.pos]
            qualified_name = "::".join([*names, class_name])
            self._symbols.append(
                ParserVtable(
                    type=marker.type,
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=qualified_name,
                    filename=self.filename,
                    base_class=marker.extra,
                )
            )

    def finish_line(self, markers: list[DecompMarker], pos: int):
        line_number, _ = get_line_column_pos(self.newlines, pos)
        for marker in markers:
            self._symbols.append(
                ParserLineSymbol(
                    type=marker.type,
                    line_number=line_number - 1,
                    module=marker.module,
                    offset=marker.offset,
                    name=f"{self.filename.name}:{line_number}",
                    filename=self.filename,
                )
            )

    def code_line(
        self,
        tokens: list[CodeToken],
        start: int,
        markers: list[DecompMarker],
    ):
        finish = find_next_token_type(tokens, start, {TokenType.CODE})
        if finish is None:
            self._alert(AlertCode.UNEXPECTED_END_OF_FILE, start)
            return

        pos, _, __ = tokens[finish]
        self.finish_line(markers, pos)

    def code_vtable(
        self,
        text: str,
        tokens: list[CodeToken],
        start: int,
        markers: list[DecompMarker],
    ):
        name = None

        finish = find_next_token_type(
            tokens, start, {TokenType.CURLY_OPEN, TokenType.SEMICOLON}
        )
        if finish is None:
            # Ran to end without finding it
            self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)
            return

        for i in range(finish, start, -1):
            start, stop, token = tokens[i]
            if token == TokenType.CODE:
                excerpt = text[start:stop]
                name = get_class_name(excerpt.strip())  # TODO
                break

        if name:
            self.finish_vtable(markers, name)
        else:
            self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)

    def code_function(
        self,
        text: str,
        tokens: list[CodeToken],
        start: int,
        markers: list[DecompMarker],
    ):
        finish = find_next_token_type(
            tokens, start, {TokenType.CURLY_OPEN, TokenType.SEMICOLON}
        )
        if finish is None:
            # Ran to end without finding it
            self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)
            return

        func_start, _, token = tokens[finish]
        if token == TokenType.SEMICOLON:
            # TODO: New error. This is not the function declaration.
            self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)
            return

        # Now find the scope that matches this function.
        try:
            __, func_end = next(
                enclosure for enclosure in self.enclosures if enclosure[0] == func_start
            )
        except StopIteration as ex:
            breakpoint()  # TODO (obviously)
            raise ex

        self.finish_function(markers, func_start, func_end)

    def code_variable(
        self,
        text: str,
        tokens: list[CodeToken],
        start: int,
        markers: list[DecompMarker],
    ):
        variable_name = None
        string_text = None

        for t_start, t_stop, token in tokens[start:]:
            if token == TokenType.CODE:
                excerpt = text[t_start:t_stop]
                variable_name = get_variable_name(excerpt)
                break

        # TODO: static vars.
        if variable_name:
            self.finish_variable(markers, variable_name)

    def code_string(
        self,
        text: str,
        tokens: list[CodeToken],
        start: int,
        markers: list[DecompMarker],
    ):
        string_obj = None

        # TODO: read from #define
        finish = find_next_token_type(
            tokens, start, {TokenType.STRING, TokenType.SEMICOLON}
        )
        if finish:
            t_start, t_stop, token = tokens[finish]
            if token == TokenType.STRING:
                excerpt = text[t_start:t_stop]
                string_obj = get_string_contents(excerpt)

        if string_obj:
            self.finish_string(markers, string_obj.text, string_obj.is_widechar)
        else:
            self._alert(AlertCode.NO_SUITABLE_NAME, start)

    def read_comment_block(self, text: str, tokens: list[CodeToken]):
        for start, stop, token in tokens:
            if start in self.found_markers:
                marker = new_match_marker(start, self.found_markers[start])
                self.handle_marker(marker)
            elif self.marker_types:
                excerpt = text[start:stop]

                for category, bucket in self.buckets.items():
                    if not bucket:
                        continue

                    markers = list(bucket.values())

                    if category == MarkerCategory.VARIABLE:
                        variable_name = get_synthetic_name(excerpt)
                        if variable_name:
                            self.finish_variable(markers, variable_name)
                        else:
                            self._alert(AlertCode.NO_SUITABLE_NAME, start)

                        bucket.clear()
                        self.marker_types.discard(category)

                    elif category == MarkerCategory.VTABLE:
                        vtable_class = get_class_name(excerpt)
                        if vtable_class is not None:
                            self.finish_vtable(markers, vtable_class)
                            bucket.clear()
                            self.marker_types.discard(category)

                    elif category == MarkerCategory.FUNCTION:
                        synthetic_name = get_synthetic_name(excerpt)
                        assert synthetic_name is not None
                        self.function_sig = synthetic_name
                        self.finish_function(markers, start, stop, lookup_by_name=True)
                        bucket.clear()
                        self.marker_types.discard(category)

                    # TODO: errors for other categories

    def read(self, text: str):
        self.found_markers = {
            m.start(): m.groups() for m in newMarkerRegex.finditer(text)
        }
        if not self.found_markers:
            return

        tokens = tokenize_code_file(text)
        self.newlines = get_newlines_from_text(text)
        self.enclosures, _ = scope_detect_churn(tokens)

        # TODO: naming and refactor
        self.scopes = get_scopes_from_tokens(text, tokens, self.enclosures)
        xxx = [(range(start, stop), name) for start, stop, name in self.scopes]
        for pos in self.found_markers.keys():
            self.scopes_for_markers[pos] = [name for span, name in xxx if pos in span]

        group_ranges = get_token_groups(text, tokens, set(self.found_markers.keys()))
        # Collect consecutive comments that are markers.
        # For each one: satisfy what is missing.

        for group_set in group_ranges:
            token_group = [tokens[i] for i in group_set]
            self.read_comment_block(text, token_group)

            # Error or completed
            if not self.marker_types:
                continue

            # index
            group_end = group_set[-1]

            # We have unfinished markers.

            for category, bucket in self.buckets.items():
                if not bucket:
                    continue

                markers = list(bucket.values())

                if category == MarkerCategory.FUNCTION:
                    self.code_function(text, tokens, group_end, markers)
                elif category == MarkerCategory.VTABLE:
                    self.code_vtable(text, tokens, group_end, markers)
                elif category == MarkerCategory.VARIABLE:
                    self.code_variable(text, tokens, group_end, markers)
                elif category == MarkerCategory.STRING:
                    self.code_string(text, tokens, group_end, markers)
                elif category == MarkerCategory.ADDRESS:
                    self.code_line(tokens, group_end, markers)

                bucket.clear()
                self.marker_types.discard(category)

            self.marker_types.clear()

        # n.b. CODE token blocks may have whitespace only
        # FUNCTION: comment (name) OR identifier between here and next scope, whichever is first.
        # .. store function and addrs for each target. to be used with STATICS.
        # GLOBAL: comment (name) OR identifier
        # .. if inside function, look it up
        # STRING: next string token.
        # VTABLE: identifier before next scope.
        # LINE: Just record it.

    def finish(self):
        # if self.state != ReaderState.SEARCH:
        #    self._alert(AlertCode.UNEXPECTED_END_OF_FILE)
        #
        # self.state = ReaderState.DONE
        pass

    def to_result(self) -> ReccmpParserResult:
        return ReccmpParserResult(
            tuple(self._symbols), tuple(self.alerts), self.filename
        )
