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
    is_marker_exact,
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
    scope_detect_churn,
    tokenize_code_file,
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
                    line_number=start_line,
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

    def finish_string(
        self, markers: list[DecompMarker], text: str, is_widechar: bool, pos: int
    ):
        line_number, _ = get_line_column_pos(self.newlines, pos)
        for marker in markers:
            self._symbols.append(
                ParserString(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=text,
                    filename=self.filename,
                    is_widechar=is_widechar,
                )
            )

    def find_function_for_static(self, module: str, pos: int) -> int | None:
        functions = self.seen_functions.get(module, [])
        for func_addr, func_span in functions:
            if pos in func_span:
                return func_addr

        return None

    def finish_variable(
        self,
        markers: list[DecompMarker],
        variable_name: str,
        pos: int,
    ):
        line_number, _ = get_line_column_pos(self.newlines, pos)

        parent_functions = {}
        for marker in markers:
            func_addr = self.find_function_for_static(marker.module, marker.pos)
            if func_addr:
                parent_functions[marker.module] = func_addr

        # If any are defined
        is_static = bool(parent_functions)

        for marker in markers:
            names = self.scopes_for_markers[marker.pos]
            qualified_name = "::".join([*names, variable_name])

            parent_function = None
            if is_static:
                if marker.module in parent_functions:
                    parent_function = parent_functions[marker.module]
                else:
                    self._alert(AlertCode.ORPHANED_STATIC_VARIABLE, marker.pos)
                    continue

            self._symbols.append(
                ParserVariable(
                    type=marker.type,
                    line_number=line_number,
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
        pos: int,
    ):
        line_number, _ = get_line_column_pos(self.newlines, pos)
        for marker in markers:
            names = self.scopes_for_markers[marker.pos]
            qualified_name = "::".join([*names, class_name])
            self._symbols.append(
                ParserVtable(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=qualified_name,
                    filename=self.filename,
                    base_class=marker.extra,
                )
            )

    def finish_line(self, markers: list[DecompMarker]):
        for marker in markers:
            line_number, _ = get_line_column_pos(self.newlines, marker.pos)
            self._symbols.append(
                ParserLineSymbol(
                    type=marker.type,
                    line_number=line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=f"{self.filename.name}:{line_number}",
                    filename=self.filename,
                )
            )

    def code_vtable(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        vtable_class = None
        vtable_pos = 0

        for start, stop, token in candidates:
            if token == TokenType.LINE_COMMENT:
                excerpt = text[start:stop]
                vtable_class = get_class_name(excerpt)
                if vtable_class is not None:
                    # Allow continuation here for `// SIZE comments`
                    self.finish_vtable(markers, vtable_class, start)
                    return

            elif token == TokenType.CURLY_OPEN:
                break

            elif token == TokenType.CODE:
                excerpt = text[start:stop]
                vtable_class = get_class_name(excerpt.strip())  # TODO
                vtable_pos = start
                break

            elif token == TokenType.SEMICOLON:
                self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)
                return

        if vtable_class:
            self.finish_vtable(markers, vtable_class, vtable_pos)
        else:
            start = candidates[0][0]
            self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)

    def code_function(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        found_sig = False
        sig_pos = 0

        for start, stop, token in candidates:
            if token == TokenType.CODE:
                # TODO: Detect function signature. Discard if we detect `if (x)`
                found_sig = True
                sig_pos = start

            if token == TokenType.LINE_COMMENT and not found_sig:
                # Allow comments between signature and curly bracket.
                # e.g. `vtable+0x08`
                excerpt = text[start:stop]
                synthetic_name = get_synthetic_name(excerpt)
                assert synthetic_name is not None
                self.function_sig = synthetic_name
                self.finish_function(markers, start, stop, lookup_by_name=True)
                return

            if token == TokenType.SEMICOLON:
                self._alert(AlertCode.NO_IMPLEMENTATION, start)
                return

            if token == TokenType.CURLY_OPEN:
                if not found_sig:
                    # TODO: alert
                    return

                try:
                    __, func_end = next(
                        enclosure
                        for enclosure in self.enclosures
                        if enclosure[0] == start
                    )
                except StopIteration as ex:
                    breakpoint()  # TODO (obviously)
                    raise ex

                self.finish_function(markers, sig_pos, func_end)
                return

        # Ran to end without finding it
        start = candidates[0][0]
        self._alert(AlertCode.MISSED_END_OF_FUNCTION, start)

    def code_variable(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        variable_name = None

        for start, stop, token in candidates:
            if token == TokenType.CODE:
                excerpt = text[start:stop]
                variable_name = get_variable_name(excerpt)
                if variable_name:
                    self.finish_variable(markers, variable_name, start)
                else:
                    self._alert(AlertCode.NO_SUITABLE_NAME, start)

                return

            elif token == TokenType.LINE_COMMENT:
                excerpt = text[start:stop]
                variable_name = get_synthetic_name(excerpt)
                if variable_name:
                    self.finish_variable(markers, variable_name, start)
                else:
                    self._alert(AlertCode.NO_SUITABLE_NAME, start)

                return

    def code_string(
        self,
        text: str,
        candidates: list[CodeToken],
        markers: list[DecompMarker],
    ):
        for start, stop, token in candidates:
            # TODO: read from #define
            if token == TokenType.STRING:
                excerpt = text[start:stop]
                string_obj = get_string_contents(excerpt)

                if string_obj:
                    self.finish_string(
                        markers, string_obj.text, string_obj.is_widechar, start
                    )

                else:
                    self._alert(AlertCode.NO_SUITABLE_NAME, start)

            elif token == TokenType.SEMICOLON:
                break

    def get_marker_sets(
        self, tokens: list[CodeToken]
    ) -> list[tuple[list[CodeToken], list[CodeToken]]]:
        markers: list[CodeToken] = []
        candidates: list[CodeToken] = []
        output = []

        for x in tokens:
            if x[0] in self.found_markers:
                # If we have begun reading candidates, this is the end of this group.
                if candidates:
                    output.append((list(markers), list(candidates)))
                    markers.clear()
                    candidates.clear()

                markers.append(x)
            elif markers:
                # Only add if we have read any markers.
                candidates.append(x)

        if markers:
            output.append((list(markers), list(candidates)))

        return output

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

        for marker_tokens, candidates in self.get_marker_sets(tokens):
            if not candidates:
                self._alert(AlertCode.UNEXPECTED_END_OF_FILE, len(text))
                continue  # ?

            for x in marker_tokens:
                marker = new_match_marker(x[0], self.found_markers[x[0]])
                if marker.type == MarkerType.UNKNOWN:
                    self._alert(AlertCode.BOGUS_MARKER, x[0], text[x[0] : x[1]])
                    continue

                self.handle_marker(marker)
                if not is_marker_exact(text, x[0]):
                    self._alert(AlertCode.BAD_DECOMP_MARKER, x[0], text[x[0] : x[1]])

            for category, bucket in self.buckets.items():
                if not bucket:
                    continue

                markers = list(bucket.values())

                if category == MarkerCategory.FUNCTION:
                    self.code_function(text, candidates, markers)

                elif category == MarkerCategory.VTABLE:
                    self.code_vtable(text, candidates, markers)

                elif category == MarkerCategory.VARIABLE:
                    self.code_variable(text, candidates, markers)

                elif category == MarkerCategory.STRING:
                    self.code_string(text, candidates, markers)

                elif category == MarkerCategory.ADDRESS:
                    self.finish_line(markers)

                bucket.clear()
                self.marker_types.discard(category)

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
