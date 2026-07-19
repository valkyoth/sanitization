#!/usr/bin/env python3
"""Reject unreviewable or low-effort CT declassification reasons in Rust source."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
METHODS = {"declassify", "declassify_u8"}
PLACEHOLDER_WORDS = {
    "fixme",
    "later",
    "placeholder",
    "tbd",
    "temp",
    "temporary",
    "todo",
    "xxx",
}
LOW_EFFORT_REASONS = {
    "because",
    "data is public",
    "is public",
    "public",
    "reason",
    "result is public",
    "secret is public",
    "test",
    "test assertion",
    "test reason",
    "value is public",
}
BOUNDARY_WORDS = {
    "assert",
    "assertion",
    "expose",
    "exposed",
    "exposes",
    "kani",
    "observe",
    "observed",
    "observes",
    "public",
    "report",
    "return",
    "returned",
    "reveal",
    "revealed",
    "reveals",
    "test",
    "verification",
    "verify",
    "wire",
}
TRUSTED_FORWARDERS = {
    Path("crates/sanitization/src/ct.rs"): "reason",
}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    column: int


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    column: int
    message: str


def advance(text: str, line: int, column: int) -> tuple[int, int]:
    newlines = text.count("\n")
    if newlines:
        return line + newlines, len(text.rsplit("\n", 1)[1]) + 1
    return line, column + len(text)


def lex(source: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1
    column = 1
    length = len(source)

    while index < length:
        start = index
        start_line = line
        start_column = column
        char = source[index]

        if char.isspace():
            index += 1
            while index < length and source[index].isspace():
                index += 1
        elif source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline == -1 else newline
        elif source.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
        else:
            raw = re.match(r'(?:br|r)(?P<hashes>#{0,255})"', source[index:])
            if raw:
                hashes = raw.group("hashes")
                prefix_length = raw.end()
                terminator = '"' + hashes
                content_start = index + prefix_length
                content_end = source.find(terminator, content_start)
                if content_end == -1:
                    index = length
                    value = source[content_start:]
                else:
                    index = content_end + len(terminator)
                    value = source[content_start:content_end]
                kind = "byte_string" if source[start] == "b" else "string"
                tokens.append(Token(kind, value, start_line, start_column))
            elif char == '"' or (char == "b" and index + 1 < length and source[index + 1] == '"'):
                is_byte = char == "b"
                index += 2 if is_byte else 1
                value_start = index
                escaped = False
                while index < length:
                    current = source[index]
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == '"':
                        break
                    index += 1
                value = source[value_start:index]
                if index < length:
                    index += 1
                tokens.append(
                    Token("byte_string" if is_byte else "string", value, start_line, start_column)
                )
            elif char.isalpha() or char == "_":
                index += 1
                while index < length and (source[index].isalnum() or source[index] == "_"):
                    index += 1
                tokens.append(Token("ident", source[start:index], start_line, start_column))
            else:
                index += 1
                tokens.append(Token("punct", char, start_line, start_column))

        line, column = advance(source[start:index], line, column)

    return tokens


def source_paths(arguments: list[str]) -> list[Path]:
    if arguments:
        candidates = [Path(argument).resolve() for argument in arguments]
    else:
        result = subprocess.run(
            ["git", "ls-files", "*.rs"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        candidates = [ROOT / line for line in result.stdout.splitlines() if line]

    paths: set[Path] = set()
    for candidate in candidates:
        if candidate.is_dir():
            paths.update(
                path.resolve()
                for path in candidate.rglob("*.rs")
                if "target" not in path.parts and ".git" not in path.parts
            )
        elif candidate.suffix == ".rs" and candidate.is_file():
            paths.add(candidate.resolve())
    return sorted(paths)


def relative_path(path: Path) -> Path:
    try:
        return path.relative_to(ROOT)
    except ValueError:
        return path


def validate_reason(reason: str) -> str | None:
    normalized = " ".join(reason.strip().lower().split())
    words = re.findall(r"[a-z0-9]+", normalized)

    if normalized in LOW_EFFORT_REASONS:
        return "reason is a generic placeholder"
    if PLACEHOLDER_WORDS.intersection(words):
        return "reason contains a placeholder word"
    if len(normalized) < 12 or len(words) < 3:
        return "reason must contain at least three meaningful words and 12 characters"
    if not BOUNDARY_WORDS.intersection(words):
        return "reason must identify the public, test, verification, or reporting boundary"
    return None


def call_arguments(tokens: list[Token], opening_index: int) -> list[list[Token]] | None:
    arguments: list[list[Token]] = [[]]
    stack = [")"]
    pairs = {"(": ")", "[": "]", "{": "}"}

    for token in tokens[opening_index + 1 :]:
        if token.value in pairs:
            stack.append(pairs[token.value])
            arguments[-1].append(token)
        elif token.value in pairs.values():
            if not stack or token.value != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return arguments
            arguments[-1].append(token)
        elif token.value == "," and len(stack) == 1:
            arguments.append([])
        else:
            arguments[-1].append(token)
    return None


def lint_path(path: Path) -> tuple[list[Finding], int]:
    tokens = lex(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    calls = 0
    relative = relative_path(path)

    for index, method in enumerate(tokens):
        if method.kind != "ident" or method.value not in METHODS:
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].value != "(":
            continue

        is_method = index >= 1 and tokens[index - 1].value == "."
        is_ufcs = (
            index >= 2
            and tokens[index - 2].value == ":"
            and tokens[index - 1].value == ":"
        )
        if not is_method and not is_ufcs:
            continue

        calls += 1
        location = Finding(relative, method.line, method.column, "")
        arguments = call_arguments(tokens, index + 1)
        reason_index = 0 if is_method else 1

        if arguments is None or len(arguments) <= reason_index:
            findings.append(
                Finding(
                    location.path,
                    location.line,
                    location.column,
                    "could not identify the reason argument",
                )
            )
            continue

        reason_tokens = arguments[reason_index]
        if len(reason_tokens) == 1 and reason_tokens[0].kind == "string":
            problem = validate_reason(reason_tokens[0].value)
            if problem:
                findings.append(
                    Finding(location.path, location.line, location.column, problem)
                )
            continue

        trusted_name = TRUSTED_FORWARDERS.get(relative)
        if (
            trusted_name is not None
            and len(reason_tokens) == 1
            and reason_tokens[0].kind == "ident"
            and reason_tokens[0].value == trusted_name
        ):
            continue

        findings.append(
            Finding(
                location.path,
                location.line,
                location.column,
                "reason must be a direct string literal at the call site",
            )
        )

    return findings, calls


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lint reason-bearing sanitization CT declassification calls."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Rust files or directories; defaults to every tracked Rust source file.",
    )
    args = parser.parse_args()

    paths = source_paths(args.paths)
    findings: list[Finding] = []
    calls = 0
    for path in paths:
        path_findings, path_calls = lint_path(path)
        findings.extend(path_findings)
        calls += path_calls

    if findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line}:{finding.column}: "
                f"weak declassification reason: {finding.message}",
                file=sys.stderr,
            )
        print(
            "declassification reason lint failed; reasons are audit labels, not runtime controls",
            file=sys.stderr,
        )
        return 1

    print(f"declassification reason lint passed ({calls} call sites in {len(paths)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
