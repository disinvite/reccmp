import enum
from typing import Iterator
from .tokenizer import TokenType


# TODO: What does this return? bool or Any?
def evaluate(tokens: list, _=None):
    # TODO
    return tokens[0][2] == "1"


class PreprocessorMode(enum.Enum):
    # Waiting for preprocessor token, passthru
    WAITING = enum.auto()

    # Store tokens until newline
    COLLECT = enum.auto()

    # Condition met at this level, passthru
    ALLOW = enum.auto()

    # Waiting for #else / #elif / #endif
    DELAY = enum.auto()

    # Collect tokens for evaluation. Return to DELAY if failed check.
    DELAY_COLLECT = enum.auto()

    # Waiting for #endif
    DONE = enum.auto()


def preprocessor(tokens) -> Iterator:
    # pylint: disable=too-many-nested-blocks
    # TODO: we're working on it
    ifdef_level = 0
    context = {}
    stack = []

    directive = ""
    mode = PreprocessorMode.WAITING
    token_stack = []

    for token in tokens:
        if token[0] != TokenType.PREPROCESSOR:
            if mode in (PreprocessorMode.WAITING, PreprocessorMode.ALLOW):
                # Passthru token
                yield token
            elif mode in (PreprocessorMode.COLLECT, PreprocessorMode.DELAY_COLLECT):
                # TODO: Need to detect line break here even if we do not emit newline tokens
                if token[0] == TokenType.NEWLINE:
                    if directive == "#if":
                        mode = (
                            PreprocessorMode.ALLOW
                            if evaluate(token_stack[0:])
                            else PreprocessorMode.DELAY
                        )
                    else:
                        variable = token_stack[0][2]  # TODO
                        if directive == "#define":
                            context[variable] = evaluate(token_stack[0:])
                        elif directive == "#undef":
                            context.pop(variable, None)
                        elif directive == "#ifdef":
                            mode = (
                                PreprocessorMode.ALLOW
                                if variable in context
                                else PreprocessorMode.DELAY
                            )
                        elif directive == "#ifndef":
                            mode = (
                                PreprocessorMode.ALLOW
                                if variable not in context
                                else PreprocessorMode.DELAY
                            )

                    token_stack.clear()
                else:
                    token_stack.append(token)

            continue

        # Else: we have a preprocessor token.

        if token[2] in ("#define", "#undef"):
            if mode in (PreprocessorMode.WAITING, PreprocessorMode.ALLOW):
                # Capture the directive because we intend to act on it
                directive = token[2]
                mode = PreprocessorMode.COLLECT

        elif token[2] in ("#ifdef", "#ifndef", "#if"):
            ifdef_level += 1
            if mode in (PreprocessorMode.WAITING, PreprocessorMode.ALLOW):
                # Capture the directive because we intend to act on it
                stack.append(ifdef_level)
                directive = token[2]
                mode = PreprocessorMode.COLLECT

        elif token[2] == "#elif":
            if stack and stack[-1] == ifdef_level:
                directive = "#if"  # mock
                if mode == PreprocessorMode.ALLOW:
                    mode = PreprocessorMode.DONE
                elif mode == PreprocessorMode.DELAY:
                    # Failed previous check, try again
                    mode = PreprocessorMode.DELAY_COLLECT

        elif token[2] == "#else":
            if stack and stack[-1] == ifdef_level:
                if mode == PreprocessorMode.ALLOW:
                    mode = PreprocessorMode.DONE
                elif mode == PreprocessorMode.DELAY:
                    mode = PreprocessorMode.ALLOW

        elif token[2] == "#endif":
            ifdef_level -= 1
            assert ifdef_level >= 0  # TODO
            if stack and stack[-1] == ifdef_level:
                # Must have been in ALLOW because we would have ignored this otherwise
                stack.pop()
                mode = PreprocessorMode.ALLOW
