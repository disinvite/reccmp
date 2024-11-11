import re
import enum
from typing import Iterator, NamedTuple
from .tokenizer import TokenType

r_whitespace = re.compile(r"\s+")


class StackAction(enum.Enum):
    CHECK = enum.auto()  # Do not passthru, test next directive at this level
    ALLOW = enum.auto()  # Passthru, do not text next directive
    IGNORE = enum.auto()  # Do not passthru, do not test next directive


class StackThing(NamedTuple):
    level: int  # which layer of ppc directive this is
    action: StackAction


def evaluate(expression: str) -> bool:
    if expression == "0":
        return False

    if expression == "1":
        return True

    return False


def preprocessor(tokens) -> Iterator:
    # pylint: disable=too-many-branches
    # TODO: we're working on it
    ifdef_level = 0
    passthru = True
    context = {}
    stack = []

    for token in tokens:
        # Hide preprocessor tokens
        if token[0] != TokenType.STUFF:
            if passthru:
                yield token
            continue

        if " " in token[2]:
            [directive, expression] = r_whitespace.split(token[2], maxsplit=2)
        else:
            directive = token[2]
            expression = ""

        if directive in ("#include", "#define", "#undef"):
            continue

        if directive == "#ifdef":
            ifdef_level += 1

            if not passthru:
                continue

            if expression in context:
                stack.append(StackThing(ifdef_level, StackAction.ALLOW))
            else:
                passthru = False
                stack.append(StackThing(ifdef_level, StackAction.CHECK))

        elif directive == "#if":
            ifdef_level += 1

            if not passthru:
                continue

            if evaluate(expression):
                stack.append(StackThing(ifdef_level, StackAction.ALLOW))
            else:
                passthru = False
                stack.append(StackThing(ifdef_level, StackAction.CHECK))

        elif directive == "#ifndef":
            ifdef_level += 1

            if not passthru:
                continue

            if expression not in context:
                stack.append(StackThing(ifdef_level, StackAction.ALLOW))
            else:
                passthru = False
                stack.append(StackThing(ifdef_level, StackAction.CHECK))
        elif directive == "#else":
            if not stack:
                # error!
                continue

            top_node = stack[-1]
            if ifdef_level == top_node.level:
                if top_node.action == StackAction.ALLOW:
                    stack.pop()
                    stack.append(StackThing(ifdef_level, StackAction.IGNORE))
                    passthru = False
                elif top_node.action == StackAction.CHECK:
                    stack.pop()
                    stack.append(StackThing(ifdef_level, StackAction.ALLOW))
                    passthru = True

        elif directive == "#elif":
            if not stack:
                # error!
                continue

            top_node = stack[-1]
            if ifdef_level == top_node.level:
                if top_node.action == StackAction.ALLOW:
                    stack.pop()
                    stack.append(StackThing(ifdef_level, StackAction.IGNORE))
                    passthru = False
                elif top_node.action == StackAction.CHECK:
                    if evaluate(expression):
                        stack.pop()
                        stack.append(StackThing(ifdef_level, StackAction.ALLOW))
                        passthru = True

        elif directive == "#endif":
            ifdef_level -= 1

            if stack and stack[-1].level > ifdef_level:
                stack.pop()

            passthru = True  # always?
