"""Allow-list parser for user and governance rule text.

Admits one `always ( wff )` unit over typed bitvector comparisons and refuses
everything else; pure stdlib so admission, apply and tooling can share it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

FRAGMENT_CODE = "RULE_FRAGMENT"
TEMPORAL_REFERENCE_PHRASE = "reads a step other than the current one"
RULE_FRAGMENT_PREFIX = "rule is outside the admitted syntax: "

SPECIAL_STREAMS = {
    "u": "the spec-update stream: writing it revises the running spec itself",
    "this": "the current-spec input: its value is the executing spec",
}

MAX_WIDTH = 384
MAX_NESTING = 32
MAX_DEPTH = 256

_WS = " \t\r\n"
_FORBIDDEN_CHAR_RE = re.compile(r"[^ \t\r\n\x21-\x7e]")
_STREAM_RE = re.compile(r"[io](?:0|[1-9][0-9]*)")
_ZERO_LEAD_STREAM_RE = re.compile(r"[io]0[0-9]+")
_TIME_EXPR_RE = re.compile(r"[ \t\r\n]*[A-Za-z0-9][A-Za-z0-9 \t\r\n+*-]*|[ \t\r\n]*-[A-Za-z0-9 \t\r\n+*-]*")
_BRACKET_AHEAD_RE = re.compile(r"[ \t\r\n]*\[")

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>[ \t\r\n]+)
  | (?P<lit>\{[ \t\r\n]*(?:\#x[0-9A-Fa-f]+|\#b[01]+|[0-9]+)[ \t\r\n]*\})
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<num>[0-9]+)
  | (?P<op><->|!<=|!>=|<-|->|\|\||\^\^|&&|!=|!<|!>|!\||!\^|!&|<=|>=|<<|>>
        |[=<>+\-*/%&|^!()?:'\[\]])
    """,
    re.X,
)

_WFF_LEVELS = ("->", "<-", "<->", "||", "^^", "&&")
_WFF_ASSOCIATIVE = frozenset({"||", "^^", "&&"})
_CMP_OPS = frozenset({"=", "!=", "<", "<=", ">", ">=", "!<", "!<=", "!>", "!>="})
_BF_OPS = frozenset({"+", "-", "*", "/", "%", "&", "|", "^", "!|", "!^", "!&", "<<", ">>"})
_BF_ASSOCIATIVE = frozenset({"+", "*", "&", "|", "^"})
_LITERAL_OPERAND_OPS = frozenset({"*", "/", "%"})


class RuleFragmentError(ValueError):
    def __init__(self, message: str, *, temporal_reference: bool = False):
        super().__init__(message)
        self.message = message
        self.temporal_reference = temporal_reference


@dataclass(frozen=True)
class StreamRef:
    io: str
    index: int
    width: int


@dataclass(frozen=True)
class RuleShape:
    nodes: int
    depth: int
    comparisons: int
    unit_bytes: int
    refs: Tuple[StreamRef, ...]
    max_width: int = 0


def clause_unit(body: str) -> str:
    return f"always ( {body} )."


def _clip(text: str, limit: int = 40) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _fail(message: str) -> RuleFragmentError:
    return RuleFragmentError(message)


def _ident_error(name: str) -> RuleFragmentError:
    if name in SPECIAL_STREAMS:
        return _fail(
            f"rule references reserved engine stream '{name}', "
            f"{SPECIAL_STREAMS[name]}."
        )
    if _STREAM_RE.fullmatch(name):
        return _fail(f"stream '{name}' must be written {name}[t]:bv[N].")
    if _ZERO_LEAD_STREAM_RE.fullmatch(name):
        return _fail(f"stream name '{name}' may not have leading zeros.")
    return _fail(f"identifier '{_clip(name)}' is not allowed in rules.")


# Token: (kind, value, position). kinds: ident, num, lit, ref, op.
_Token = Tuple[str, object, int]


def _tokenize(text: str) -> List[_Token]:
    tokens: List[_Token] = []
    pos = 0
    end = len(text)
    paren = 0
    while pos < end:
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            ch = text[pos]
            if ch in "{}":
                raise _fail(
                    "braced constants must be a plain integer, #x or #b literal."
                )
            if ch == "#":
                raise _fail("'#' is only allowed inside a braced #x or #b literal.")
            raise _fail(f"character {ch!r} is not allowed in rules.")
        kind = m.lastgroup
        value = m.group()
        if kind == "ws":
            pos = m.end()
            continue
        if kind == "ident":
            ahead = _BRACKET_AHEAD_RE.match(text, m.end())
            if ahead is not None and value != "bv":
                tokens.append(_lex_ref(text, value, m.end(), ahead.end()))
                pos = tokens[-1][2]
                continue
            tokens.append(("ident", value, pos))
        elif kind == "num":
            tokens.append(("num", value, pos))
        elif kind == "lit":
            tokens.append(("lit", value, pos))
        else:
            if value == "(":
                paren += 1
                if paren > MAX_NESTING + 1:
                    raise _fail(
                        f"parentheses are nested more than {MAX_NESTING} levels deep."
                    )
            elif value == ")":
                paren -= 1
                if paren < 0:
                    raise _fail("unbalanced parentheses.")
            tokens.append(("op", value, pos))
        pos = m.end()
    if paren != 0:
        raise _fail("unbalanced parentheses.")
    return tokens


def _lex_ref(text: str, name: str, name_end: int, bracket_end: int) -> _Token:
    """Reads `name[...]`; the returned token's position is where lexing resumes."""
    if name in SPECIAL_STREAMS:
        raise _ident_error(name)
    if not _STREAM_RE.fullmatch(name):
        if _ZERO_LEAD_STREAM_RE.fullmatch(name):
            raise _ident_error(name)
        raise _fail(
            f"rule references unknown stream '{_clip(name)}'; only i<N> inputs "
            f"and o<N> outputs may be indexed."
        )
    if bracket_end != name_end + 1:
        raise _fail(f"no whitespace is allowed between '{name}' and '['.")
    close = text.find("]", bracket_end)
    if close == -1:
        raise _fail(f"unterminated '[' after '{name}'.")
    content = text[bracket_end:close]
    if content != "t":
        if content.strip() == "t":
            raise _fail(f"write {name}[t] with no whitespace inside the brackets.")
        if not _TIME_EXPR_RE.fullmatch(content):
            raise _fail(f"malformed index after '{name}['.")
        shown = f"{name}[{_clip(content.strip())}]"
        raise RuleFragmentError(
            f"rule {TEMPORAL_REFERENCE_PHRASE} ({shown}); user rules may "
            f"reference [t] only.",
            temporal_reference=True,
        )
    return ("ref", (name[0], int(name[1:])), close + 1)


class _Node:
    __slots__ = ("nodes", "depth", "comparisons", "literal")

    def __init__(self, nodes: int, depth: int, comparisons: int, literal: bool = False):
        if depth > MAX_DEPTH:
            raise _fail(f"rule expression is deeper than {MAX_DEPTH} levels.")
        self.nodes = nodes
        self.depth = depth
        self.comparisons = comparisons
        self.literal = literal


def _leaf(literal: bool = False) -> _Node:
    return _Node(1, 1, 0, literal)


def _join(*parts: _Node, comparison: bool = False) -> _Node:
    return _Node(
        1 + sum(p.nodes for p in parts),
        1 + max(p.depth for p in parts),
        sum(p.comparisons for p in parts) + (1 if comparison else 0),
    )


class _Parser:
    def __init__(self, tokens: List[_Token]):
        self.tokens = tokens
        self.pos = 0
        self.nest = 0
        self.widths: dict = {}
        self.literal_width = 0
        self.match = self._match_parens(tokens)

    @staticmethod
    def _match_parens(tokens: List[_Token]) -> dict:
        stack: List[int] = []
        match = {}
        for i, (kind, value, _) in enumerate(tokens):
            if kind == "op" and value == "(":
                stack.append(i)
            elif kind == "op" and value == ")":
                match[stack.pop()] = i
        return match

    def peek(self, offset: int = 0) -> Optional[_Token]:
        i = self.pos + offset
        return self.tokens[i] if i < len(self.tokens) else None

    def peek_op(self, offset: int = 0) -> Optional[str]:
        tok = self.peek(offset)
        return tok[1] if tok is not None and tok[0] == "op" else None

    def expect_op(self, op: str) -> None:
        tok = self.peek()
        if tok is None:
            raise _fail(f"unexpected end of rule; expected '{op}'.")
        if tok[0] != "op" or tok[1] != op:
            raise self.unexpected(tok, f"expected '{op}'")
        self.pos += 1

    @staticmethod
    def unexpected(tok: _Token, note: str = "") -> RuleFragmentError:
        kind, value, _ = tok
        if kind == "ident":
            return _ident_error(value)
        if kind == "ref":
            shown = f"{value[0]}{value[1]}[t]"
        else:
            shown = value
        suffix = f" ({note})" if note else ""
        return _fail(f"unexpected {_clip(str(shown))!r}{suffix}.")

    def enter(self) -> None:
        self.nest += 1
        if self.nest > MAX_NESTING:
            raise _fail(f"rule is nested more than {MAX_NESTING} levels deep.")

    def leave(self) -> None:
        self.nest -= 1

    def annotation(self, *, required: bool) -> Optional[int]:
        if self.peek_op() != ":":
            if required:
                raise _fail("streams and braced constants must carry a :bv[N] type.")
            return None
        nxt = self.peek(1)
        if nxt is None or nxt[0] != "ident" or nxt[1] != "bv":
            if not required:
                return None
            raise _fail("only the :bv[N] type is allowed.")
        self.pos += 2
        self.expect_op("[")
        tok = self.peek()
        if tok is None or tok[0] != "num":
            raise _fail("bv[N] needs a decimal width.")
        digits = tok[1]
        if len(digits) > 1 and digits.startswith("0"):
            raise _fail(f"bit width '{digits}' may not have leading zeros.")
        width = int(digits)
        if not 1 <= width <= MAX_WIDTH:
            raise _fail(f"bit width must be between 1 and {MAX_WIDTH}.")
        self.pos += 1
        self.expect_op("]")
        return width

    def note_width(self, io: str, index: int, width: int) -> None:
        key = (io, index)
        known = self.widths.setdefault(key, width)
        if known != width:
            raise _fail(
                f"stream {io}{index} is typed bv[{known}] and bv[{width}] in one rule."
            )

    def bf_primary(self) -> _Node:
        tok = self.peek()
        if tok is None:
            raise _fail("unexpected end of rule.")
        kind, value, _ = tok
        if kind == "op" and value == "(":
            self.pos += 1
            self.enter()
            node = self.bf_expr()
            self.leave()
            self.expect_op(")")
            return self.postfix(node)
        if kind == "ref":
            self.pos += 1
            width = self.annotation(required=True)
            self.note_width(value[0], value[1], width)
            return self.postfix(_leaf())
        if kind == "lit":
            self.pos += 1
            body = value[1:-1].strip()
            if body.startswith("#x"):
                number = int(body[2:], 16)
            elif body.startswith("#b"):
                number = int(body[2:], 2)
            else:
                if len(body) > 1 and body.startswith("0"):
                    raise _fail("decimal constants may not have leading zeros.")
                number = int(body)
            width = self.annotation(required=True)
            self.literal_width = max(self.literal_width, width)
            if number >= 1 << width:
                raise _fail(f"constant {_clip(body)} does not fit in bv[{width}].")
            return self.postfix(_leaf(literal=True))
        if kind == "num":
            if value not in ("0", "1"):
                raise _fail(
                    f"numeral '{_clip(value)}' is not allowed; use 0, 1 or a "
                    f"braced typed constant."
                )
            self.pos += 1
            width = self.annotation(required=False)
            if width is not None:
                self.literal_width = max(self.literal_width, width)
            return self.postfix(_leaf(literal=True))
        raise self.unexpected(tok)

    def postfix(self, node: _Node) -> _Node:
        while self.peek_op() == "'":
            self.pos += 1
            node = _join(node)
        return node

    def bf_expr(self) -> _Node:
        left = self.bf_primary()
        kind: Optional[str] = None
        while True:
            op = self.peek_op()
            if op not in _BF_OPS:
                return left
            if kind is None:
                kind = op
            elif op != kind:
                raise _fail(
                    f"operators '{kind}' and '{op}' in one expression need "
                    f"parentheses."
                )
            elif op not in _BF_ASSOCIATIVE:
                raise _fail(f"a chain of '{op}' needs parentheses.")
            self.pos += 1
            right = self.bf_primary()
            if op in _LITERAL_OPERAND_OPS and not (left.literal or right.literal):
                raise _fail(f"'{op}' needs a constant as one operand.")
            left = _join(left, right)

    def comparison(self) -> _Node:
        left = self.bf_expr()
        op = self.peek_op()
        if op not in _CMP_OPS:
            tok = self.peek()
            if tok is None:
                raise _fail("unexpected end of rule; expected a comparison.")
            raise self.unexpected(tok, "expected a comparison operator")
        self.pos += 1
        right = self.bf_expr()
        if self.peek_op() in _CMP_OPS:
            raise _fail("comparisons cannot be chained.")
        return _join(left, right, comparison=True)

    def unary(self) -> _Node:
        negations = 0
        while self.peek_op() == "!":
            negations += 1
            self.pos += 1
        tok = self.peek()
        if tok is None:
            raise _fail("unexpected end of rule.")
        node: _Node
        if tok[0] == "op" and tok[1] == "(":
            after = self.tokens[self.match[self.pos] + 1:self.match[self.pos] + 2]
            starts_bf = bool(after) and after[0][0] == "op" and (
                after[0][1] in _CMP_OPS or after[0][1] in _BF_OPS or after[0][1] == "'"
            )
            if starts_bf:
                node = self.comparison()
            else:
                self.pos += 1
                self.enter()
                inner = self.wff()
                self.leave()
                self.expect_op(")")
                node = _Node(inner.nodes, inner.depth, inner.comparisons)
        else:
            node = self.comparison()
        for _ in range(negations):
            node = _join(node)
        return node

    def level(self, index: int) -> _Node:
        if index == len(_WFF_LEVELS):
            return self.unary()
        op = _WFF_LEVELS[index]
        left = self.level(index + 1)
        while self.peek_op() == op:
            self.pos += 1
            right = self.level(index + 1)
            left = _join(left, right)
            if op not in _WFF_ASSOCIATIVE and self.peek_op() == op:
                raise _fail(f"a chain of '{op}' needs parentheses.")
        return left

    def wff(self) -> _Node:
        cond = self.level(0)
        if self.peek_op() != "?":
            return cond
        self.pos += 1
        then = self.level(0)
        self.expect_op(":")
        other = self.level(0)
        if self.peek_op() == "?":
            raise _fail("a nested conditional needs parentheses.")
        return _join(cond, then, other)


def _parse(text: str) -> RuleShape:
    if not isinstance(text, str):
        raise _fail("rule text must be a string.")
    bad = _FORBIDDEN_CHAR_RE.search(text)
    if bad is not None:
        raise _fail(f"character {bad.group()!r} is not allowed in rules.")
    body = text.rstrip(_WS)
    if body.endswith("."):
        body = body[:-1]
    tokens = _tokenize(body)
    if not tokens:
        raise _fail("empty rule.")
    first = tokens[0]
    if first[0] != "ident" or first[1] != "always":
        raise _fail("a rule must be a single always ( ... ) unit.")
    parser = _Parser(tokens)
    parser.pos = 1
    if parser.peek_op() != "(":
        raise _fail("a rule must be a single always ( ... ) unit.")
    parser.pos = 2
    node = parser.wff()
    if parser.peek_op() != ")" or parser.pos != len(tokens) - 1:
        tail = parser.peek()
        if tail is not None and not (tail[0] == "op" and tail[1] == ")"):
            raise parser.unexpected(tail)
        raise _fail("a rule must be a single always ( ... ) unit with nothing after it.")
    refs = tuple(
        StreamRef(io, index, width)
        for (io, index), width in sorted(parser.widths.items())
    )
    return RuleShape(
        nodes=node.nodes,
        depth=node.depth,
        comparisons=node.comparisons,
        unit_bytes=len(text.encode("utf-8")),
        refs=refs,
        max_width=max([parser.literal_width, *parser.widths.values()]),
    )


def parse_rule_unit(text: str) -> RuleShape:
    try:
        return _parse(text)
    except RecursionError:
        raise _fail("rule is nested too deeply.") from None
