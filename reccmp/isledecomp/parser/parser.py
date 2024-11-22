# C++ file parser

import enum
from typing import List, Iterator, Optional
from .util import (
    get_class_name,
    get_synthetic_name,
    get_string_contents,
    get_variable_name,
)
from .marker import (
    DecompMarker,
    MarkerCategory,
    match_marker,
    is_marker_exact,
)
from .node import (
    ParserSymbol,
    ParserFunction,
    ParserVariable,
    ParserVtable,
    ParserString,
)
from .error import ParserAlert, ParserError
from .tokenizer import TokenType, tokenize
from .preprocessor import preprocessor


class ReaderState(enum.Enum):
    # Waiting for the next annotation marker
    SEARCH = enum.auto()
    # Read a function annotation, waiting for nameref comment or code tokens
    FUNCTION_PENDING = enum.auto()
    # Collecting code tokens to find start of function
    FUNCTION_COLLECT = enum.auto()
    # We read one of the nameref-only function annotations. Waiting for comment
    FUNCTION_NAMEREF = enum.auto()
    # Inside the function, waiting for ending curly brace.
    IN_FUNC = enum.auto()
    # Read a variable/string annotation, waiting for nameref comment or code tokens
    DATA_PENDING = enum.auto()
    # Collecting code tokens to identify variable
    DATA_COLLECT = enum.auto()
    # Same as above two states but we are inside a function
    IN_FUNC_DATA_PENDING = enum.auto()
    IN_FUNC_DATA_COLLECT = enum.auto()
    # for vtable
    VTABLE_PENDING = enum.auto()
    VTABLE_COLLECT = enum.auto()
    #
    DONE = enum.auto()


class MarkerDict:
    def __init__(self) -> None:
        self.markers: dict = {}

    def insert(self, marker: DecompMarker) -> bool:
        """Return True if this insert would overwrite"""
        if marker.key in self.markers:
            return True

        self.markers[marker.key] = marker
        return False

    def query(
        self, category: MarkerCategory, module: str, extra: Optional[str] = None
    ) -> Optional[DecompMarker]:
        return self.markers.get((category, module, extra))

    def iter(self) -> Iterator[DecompMarker]:
        for _, marker in self.markers.items():
            yield marker

    def empty(self):
        self.markers = {}


class CurlyManager:
    """Overly simplified scope manager"""

    _stack: list[tuple[str, int]]
    _level: int
    _pending: Optional[str]
    _state: int

    def __init__(self):
        self.reset()

    @property
    def level(self) -> int:
        return self._level

    def reset(self):
        self._stack = []
        self._level = 0

        self._pending = None
        self._state = 0

    def _new_scope(self, scope: str):
        self._stack.append((scope, self._level))

    def _pop(self):
        """Pop stack safely"""
        if self._level > 0:
            self._level -= 1

        while self._stack and self._stack[-1][1] >= self._level:
            self._stack.pop()

    def get_prefix(self, name: Optional[str] = None) -> str:
        """Combine all scope names and append the given name"""
        scopes = [scope for (scope, _) in self._stack]

        if name is not None and name not in scopes:
            scopes.append(name)

        return "::".join(scopes)

    def read_token(self, token):
        (token_type, _, value) = token
        if token_type == TokenType.OPERATOR:
            self._state = 0
            if value == "{":
                if self._pending is not None:
                    self._new_scope(self._pending)
                    self._pending = None
                self._level += 1
            elif value == "}":
                self._pop()
            elif value == ";":
                self._pending = None
        elif token_type == TokenType.IDENTIFIER:
            if self._state == 0:
                if value in ("class", "struct", "namespace"):
                    self._state = 1
            elif self._state == 1:
                self._pending = value

    def read_line(self, raw_line: str):
        """Read a line of code and update the stack."""
        for token in tokenize(raw_line):
            self.read_token(token)


class DecompParser:
    # pylint: disable=too-many-instance-attributes
    # Could combine output lists into a single list to get under the limit,
    # but not right now
    def __init__(self) -> None:
        # The lists to be populated as we parse
        self._symbols: List[ParserSymbol] = []
        self.alerts: List[ParserAlert] = []

        self.line_number: int = 0
        self.state: ReaderState = ReaderState.SEARCH

        self.last_line: str = ""
        self.last_token = None

        self.token_stack = []

        self.curly = CurlyManager()

        # To allow for multiple markers where code is shared across different
        # modules, save lists of compatible markers that appear in sequence
        self.fun_markers = MarkerDict()
        self.var_markers = MarkerDict()
        self.tbl_markers = MarkerDict()

        # To handle functions that are entirely indented (i.e. those defined
        # in class declarations), remember how many whitespace characters
        # came before the opening curly brace and match that up at the end.
        # This should give us the same or better accuracy for a well-formed file.
        # The alternative is counting the curly braces on each line
        # but that's probably too cumbersome.
        self.curly_indent_stops: int = 0

        # For non-synthetic functions, save the line number where the function begins
        # (i.e. where we see the curly brace) along with the function signature.
        # We will need both when we reach the end of the function.
        self.function_start: int = 0
        self.function_sig: str = ""

    def reset(self):
        self._symbols = []
        self.alerts = []

        self.line_number = 0
        self.state = ReaderState.SEARCH

        self.last_line = ""

        self.fun_markers.empty()
        self.var_markers.empty()
        self.tbl_markers.empty()

        self.curly_indent_stops = 0
        self.function_start = 0
        self.function_sig = ""

        self.curly.reset()

    @property
    def functions(self) -> List[ParserFunction]:
        return [s for s in self._symbols if isinstance(s, ParserFunction)]

    @property
    def vtables(self) -> List[ParserVtable]:
        return [s for s in self._symbols if isinstance(s, ParserVtable)]

    @property
    def variables(self) -> List[ParserVariable]:
        return [s for s in self._symbols if isinstance(s, ParserVariable)]

    @property
    def strings(self) -> List[ParserString]:
        return [s for s in self._symbols if isinstance(s, ParserString)]

    def iter_symbols(self, module: Optional[str] = None) -> Iterator[ParserSymbol]:
        for s in self._symbols:
            if module is None or s.module == module:
                yield s

    def _recover(self):
        """We hit a syntax error and need to reset temp structures"""
        self.state = ReaderState.SEARCH
        self.fun_markers.empty()
        self.var_markers.empty()
        self.tbl_markers.empty()

    def _syntax_warning(self, code):
        self.alerts.append(
            ParserAlert(
                line_number=self.line_number,
                code=code,
                line=self.last_token,
            )
        )

    def _syntax_error(self, code):
        self._syntax_warning(code)
        self._recover()

    def _function_starts_here(self):
        self.function_start = self.line_number

    def _function_marker(self, marker: DecompMarker):
        if self.fun_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)
        self.state = ReaderState.FUNCTION_PENDING

    def _nameref_marker(self, marker: DecompMarker):
        """Functions explicitly referenced by name are set here"""
        if self.fun_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)
        self.state = ReaderState.FUNCTION_NAMEREF

    def _function_done(self, lookup_by_name: bool = False, unexpected: bool = False):
        end_line = self.line_number
        if unexpected:
            # If we missed the end of the previous function, assume it ended
            # on the previous line and that whatever we are tracking next
            # begins on the current line.
            end_line -= 1

        for marker in self.fun_markers.iter():
            self._symbols.append(
                ParserFunction(
                    type=marker.type,
                    line_number=self.function_start,
                    module=marker.module,
                    offset=marker.offset,
                    name=self.function_sig,
                    lookup_by_name=lookup_by_name,
                    end_line=end_line,
                )
            )

        self.fun_markers.empty()
        self.curly_indent_stops = 0
        self.state = ReaderState.SEARCH

    def _vtable_marker(self, marker: DecompMarker):
        if self.tbl_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)
        self.state = ReaderState.VTABLE_PENDING

    def _vtable_done(self, class_name: str = None):
        if class_name is None:
            # Best we can do
            class_name = self.last_line.strip()

        for marker in self.tbl_markers.iter():
            self._symbols.append(
                ParserVtable(
                    type=marker.type,
                    line_number=self.line_number,
                    module=marker.module,
                    offset=marker.offset,
                    name=self.curly.get_prefix(class_name),
                    base_class=marker.extra,
                )
            )

        self.tbl_markers.empty()
        self.state = ReaderState.SEARCH

    def _variable_marker(self, marker: DecompMarker):
        if self.var_markers.insert(marker):
            self._syntax_warning(ParserError.DUPLICATE_MODULE)

        if self.state in (ReaderState.IN_FUNC, ReaderState.IN_FUNC_DATA_PENDING):
            self.state = ReaderState.IN_FUNC_DATA_PENDING
        else:
            self.state = ReaderState.DATA_PENDING

    def _variable_done(
        self, variable_name: Optional[str] = None, string_value: Optional[str] = None
    ):
        if variable_name is None and string_value is None:
            self._syntax_error(ParserError.NO_SUITABLE_NAME)
            return

        for marker in self.var_markers.iter():
            if marker.is_string():
                self._symbols.append(
                    ParserString(
                        type=marker.type,
                        line_number=self.line_number,
                        module=marker.module,
                        offset=marker.offset,
                        name=string_value,
                    )
                )
            else:
                parent_function = None
                is_static = self.state == ReaderState.IN_FUNC_DATA_COLLECT

                # If this is a static variable, we need to get the function
                # where it resides so that we can match it up later with the
                # mangled names of both variable and function from cvdump.
                if is_static:
                    fun_marker = self.fun_markers.query(
                        MarkerCategory.FUNCTION, marker.module
                    )

                    if fun_marker is None:
                        self._syntax_warning(ParserError.ORPHANED_STATIC_VARIABLE)
                        continue

                    parent_function = fun_marker.offset

                self._symbols.append(
                    ParserVariable(
                        type=marker.type,
                        line_number=self.line_number,
                        module=marker.module,
                        offset=marker.offset,
                        name=self.curly.get_prefix(variable_name),
                        is_static=is_static,
                        parent_function=parent_function,
                    )
                )

        self.var_markers.empty()
        if self.state == ReaderState.IN_FUNC_DATA_COLLECT:
            self.state = ReaderState.IN_FUNC
        else:
            self.state = ReaderState.SEARCH

    def _handle_marker(self, marker: DecompMarker):
        # Cannot handle any markers between function sig and opening curly brace
        if self.state == ReaderState.FUNCTION_COLLECT:
            self._syntax_error(ParserError.UNEXPECTED_MARKER)
            return

        # If we are inside a function, the only markers we accept are:
        # GLOBAL, indicating a static variable
        # STRING, indicating a literal string.
        # Otherwise we assume that the parser missed the end of the function
        # and we have moved on to something else.
        # This is unlikely to occur with well-formed code, but
        # we can recover easily by just ending the function here.
        if self.state == ReaderState.IN_FUNC and not marker.allowed_in_func():
            self._syntax_warning(ParserError.MISSED_END_OF_FUNCTION)
            self._function_done(unexpected=True)

        # TODO: How uncertain are we of detecting the end of a function
        # in a clang-formatted file? For now we assume we have missed the
        # end if we detect a non-GLOBAL marker while state is IN_FUNC.
        # Maybe these cases should be syntax errors instead

        if marker.is_regular_function():
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.FUNCTION_PENDING,
            ):
                # We will allow multiple offsets if we have just begun
                # the code block, but not after we hit the curly brace.
                self._function_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker.is_explicit_byname():
            top_marker = next(self.fun_markers.iter(), None)
            if top_marker is None or top_marker.type == marker.type:
                self._nameref_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        # Strings and variables are almost the same thing
        elif marker.is_string() or marker.is_variable():
            if self.state in (
                ReaderState.SEARCH,
                ReaderState.DATA_PENDING,
                ReaderState.IN_FUNC,
                ReaderState.IN_FUNC_DATA_PENDING,
            ):
                self._variable_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        elif marker.is_vtable():
            if self.state in (ReaderState.SEARCH, ReaderState.VTABLE_PENDING):
                self._vtable_marker(marker)
            else:
                self._syntax_error(ParserError.INCOMPATIBLE_MARKER)

        else:
            self._syntax_warning(ParserError.BOGUS_MARKER)

    def _squash_token_stack(self) -> str:
        whitespace_stack = []
        last_idx = -1
        for token in self.token_stack:
            if last_idx > 0:
                gap = token[1][1] - last_idx
                whitespace_stack.append(" " * gap)

            if token[0] != TokenType.NEWLINE:
                last_idx = token[1][1] + len(token[2])
                whitespace_stack.append(token[2])

        return "".join(whitespace_stack)

    def _get_function_name(self):
        substack = []
        recording = False
        for token in self.token_stack[::-1]:
            if recording:
                if substack:
                    if substack[-1][0] == token[0]:
                        break
                    substack.insert(0, token)
                elif token[0] == TokenType.IDENTIFIER:
                    substack = [token]

            # We recorded up to the opening curly brace. Rewind to the paren
            elif token[2] == "(":
                recording = True

        return "".join(value for (_, __, value) in substack)

    def _get_vtable_name(self):
        substack = []
        for token in self.token_stack[::-1]:
            # Drop stack if we detect that we have read a superclass
            if token[2] == ":":
                substack.clear()

            if substack:
                if token[2] in ("class", "struct"):
                    break
                substack.insert(0, token)
            elif token[0] == TokenType.IDENTIFIER:
                substack = [token]

        return "".join(value for (_, __, value) in substack)

    def read_token(self, token):
        # pylint: disable=too-many-branches
        # pylint: disable=too-many-statements
        # pylint: disable=too-many-return-statements
        # Gimme a break!!!
        if self.state == ReaderState.DONE:
            return

        self.last_token = token  # TODO: error reporting works this way for now
        self.line_number = token[1][0]

        # TODO!
        if token[0] == TokenType.NEWLINE:
            if self.state in (
                ReaderState.FUNCTION_PENDING,
                ReaderState.DATA_PENDING,
                ReaderState.IN_FUNC_DATA_PENDING,
                ReaderState.VTABLE_PENDING,
            ):
                self._syntax_warning(ParserError.UNEXPECTED_BLANK_LINE)
            return

        if token[0] == TokenType.LINE_COMMENT:
            # TODO: temporary hack to resolve confusing marker stack
            # of GLOBAL plus array with other markers inside it
            if self.state in (
                ReaderState.FUNCTION_COLLECT,
                ReaderState.DATA_COLLECT,
                ReaderState.IN_FUNC_DATA_COLLECT,
                ReaderState.VTABLE_COLLECT,
            ):
                return
            marker = match_marker(token[2])
            if marker is not None:
                # TODO: what's the best place for this?
                # Does it belong with reading or marker handling?
                if not is_marker_exact(token[2]):
                    self._syntax_warning(ParserError.BAD_DECOMP_MARKER)
                self._handle_marker(marker)
                return

            if self.state in (
                ReaderState.FUNCTION_PENDING,
                ReaderState.FUNCTION_NAMEREF,
            ):
                # Explicit nameref functions provide the function name
                # on the next line (in a // comment)
                name = get_synthetic_name(token[2])
                if name is None:
                    self._syntax_error(ParserError.BAD_NAMEREF)
                else:
                    self.function_sig = name
                    self._function_starts_here()
                    self._function_done(lookup_by_name=True)

            elif self.state in (
                ReaderState.DATA_PENDING,
                ReaderState.IN_FUNC_DATA_PENDING,
            ):
                name = get_synthetic_name(token[2])
                # TODO: Ignore comments here?
                # We don't have much choice for array variables.
                if name is not None:
                    # TODO: drop string annotations if any are pending. syntax warning
                    self._variable_done(name, None)

            elif self.state == ReaderState.VTABLE_PENDING:
                vtable_class = get_class_name(token[2])
                if vtable_class is not None:
                    # Ignore comments (like `// SIZE 0x100`) that don't match
                    self._vtable_done(class_name=vtable_class)

            return

        self.curly.read_token(token)

        # We require a nameref but got code instead
        if self.state == ReaderState.FUNCTION_NAMEREF:
            self._syntax_error(ParserError.BAD_NAMEREF)
            return

        # We read a code (non-comment) token, so flip to collect state.
        # Fallthrough here because we start collecting with THIS token.
        if self.state == ReaderState.FUNCTION_PENDING:
            self.state = ReaderState.FUNCTION_COLLECT

        if self.state == ReaderState.DATA_PENDING:
            self.state = ReaderState.DATA_COLLECT

        if self.state == ReaderState.IN_FUNC_DATA_PENDING:
            self.state = ReaderState.IN_FUNC_DATA_COLLECT

        if self.state == ReaderState.VTABLE_PENDING:
            self.state = ReaderState.VTABLE_COLLECT

        #####

        if self.state == ReaderState.FUNCTION_COLLECT:
            if token[2] == ";":
                self._syntax_error(ParserError.NO_IMPLEMENTATION)
            elif token[2] == "{":
                name = self._get_function_name()
                if name == "":
                    self._syntax_warning(ParserError.MISSED_START_OF_FUNCTION)

                self.function_sig = name
                self.function_start = token[1][0]  # line number of curly
                # Minus one here. Scope manager read the "{" earlier
                # and bumped the level.
                self.curly_indent_stops = self.curly.level - 1
                self.state = ReaderState.IN_FUNC
                self.token_stack.clear()
            else:
                self.token_stack.append(token)

        elif self.state == ReaderState.IN_FUNC:
            if token[2] == "}" and self.curly.level <= self.curly_indent_stops:
                self._function_done()

        elif self.state in (ReaderState.DATA_COLLECT, ReaderState.IN_FUNC_DATA_COLLECT):
            if token[2] == ";":
                string_value = get_string_contents(self._squash_token_stack())
                variable_name = get_variable_name(self._squash_token_stack())

                global_markers_queued = any(
                    m.is_variable() for m in self.var_markers.iter()
                )

                return_statement = any(
                    value == "return" for (_, __, value) in self.token_stack
                )

                if global_markers_queued and return_statement:
                    self._syntax_error(ParserError.GLOBAL_NOT_VARIABLE)
                    return

                self._variable_done(variable_name, string_value)
                self.token_stack.clear()
            elif token[0] not in (TokenType.LINE_COMMENT, TokenType.BLOCK_COMMENT):
                # TODO: comments captured upstream?
                self.token_stack.append(token)

        elif self.state == ReaderState.VTABLE_COLLECT:
            if token[2] == ";":
                self._syntax_error(ParserError.NO_IMPLEMENTATION)  # TODO
            elif token[2] == "{":
                vtable_class = self._get_vtable_name()
                self._vtable_done(class_name=vtable_class)
                self.token_stack.clear()
            else:
                self.token_stack.append(token)

    def read(self, text: str):
        for token in preprocessor(tokenize(text)):
            self.read_token(token)

    def finish(self):
        if self.state != ReaderState.SEARCH:
            self._syntax_warning(ParserError.UNEXPECTED_END_OF_FILE)

        self.state = ReaderState.DONE
