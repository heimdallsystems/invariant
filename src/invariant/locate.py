"""
Source locations for policy statements, for SARIF regions.

Checks work on parsed JSON, which has no line numbers. This module reads a
policy file's raw text and finds where its top-level "Statement" value and
each statement in it start and end, so a SARIF result can point at the
statement a finding is about. GitHub code scanning needs a line to match an
alert to the lines a pull request changed, and GitLab de-duplicates
findings that share a rule and file but have no line.

Positions follow SARIF 2.1.0 defaults: 1-based lines and columns, columns
counted in UTF-16 code units, endColumn exclusive.
"""
import json
import re
from dataclasses import dataclass
from json.decoder import scanstring
from typing import Optional

_WHITESPACE = re.compile(r"[ \t\n\r]*")
_DECODER = json.JSONDecoder()


@dataclass(frozen=True)
class Span:
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def to_sarif_region(self) -> dict:
        return {
            "startLine": self.start_line,
            "startColumn": self.start_column,
            "endLine": self.end_line,
            "endColumn": self.end_column,
        }


@dataclass(frozen=True)
class PolicyLocations:
    # From the "Statement" key through the end of its value.
    statement_block: Span
    # One span per statement, in document order. A "Statement" that is a
    # single object (allowed by the IAM grammar) is one statement.
    statements: list


class _Positions:
    def __init__(self, text: str):
        self.text = text
        self.line_starts = [0]
        for match in re.finditer("\n", text):
            self.line_starts.append(match.end())

    def _line_col(self, offset: int) -> tuple:
        # Binary search for the last line start <= offset.
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        prefix = self.text[self.line_starts[lo]:offset]
        column = len(prefix.encode("utf-16-le")) // 2 + 1
        return lo + 1, column

    def span(self, start: int, end: int) -> Span:
        start_line, start_column = self._line_col(start)
        end_line, end_column = self._line_col(end)
        return Span(start_line, start_column, end_line, end_column)


def _skip(text: str, i: int) -> int:
    return _WHITESPACE.match(text, i).end()


def locate_statements(text: str) -> Optional[PolicyLocations]:
    """
    Locations of the top-level "Statement" value and each statement in it,
    or None if the text isn't a JSON object with a "Statement" key. If the
    key appears more than once, the last one wins, as with json.loads.
    """
    try:
        return _locate(text)
    except (ValueError, IndexError):
        return None


def _locate(text: str) -> Optional[PolicyLocations]:
    positions = _Positions(text)
    i = _skip(text, 1 if text.startswith("﻿") else 0)
    if text[i] != "{":
        return None
    i += 1
    found = None
    while True:
        i = _skip(text, i)
        if text[i] == "}":
            break
        if text[i] != '"':
            return None
        key_start = i
        key, i = scanstring(text, i + 1)
        i = _skip(text, i)
        if text[i] != ":":
            return None
        value_start = _skip(text, i + 1)
        _, value_end = _DECODER.raw_decode(text, value_start)
        if key == "Statement":
            found = (key_start, value_start, value_end)
        i = _skip(text, value_end)
        if text[i] == ",":
            i += 1
            continue
        if text[i] == "}":
            break
        return None

    if found is None:
        return None
    key_start, value_start, value_end = found
    statements = []
    if text[value_start] == "[":
        j = _skip(text, value_start + 1)
        if text[j] != "]":
            while True:
                _, element_end = _DECODER.raw_decode(text, j)
                statements.append(positions.span(j, element_end))
                j = _skip(text, element_end)
                if text[j] == ",":
                    j = _skip(text, j + 1)
                    continue
                break
    elif text[value_start] == "{":
        statements.append(positions.span(value_start, value_end))
    return PolicyLocations(
        statement_block=positions.span(key_start, value_end),
        statements=statements,
    )


def locate_file(path: str) -> Optional[PolicyLocations]:
    try:
        with open(path, encoding="utf-8") as f:
            return locate_statements(f.read())
    except (OSError, UnicodeDecodeError):
        return None


def region_for(path: str, statement_index: Optional[int]) -> Optional[dict]:
    """
    The SARIF region for a finding about `statement_index` in `path`: that
    statement if it exists, otherwise the whole "Statement" block (the
    statement was deleted, or no single statement could be named). None if
    the file can't be read or has no "Statement" key.
    """
    locations = locate_file(path)
    if locations is None:
        return None
    if statement_index is not None and 0 <= statement_index < len(locations.statements):
        return locations.statements[statement_index].to_sarif_region()
    return locations.statement_block.to_sarif_region()
