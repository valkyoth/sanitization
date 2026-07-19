#!/usr/bin/env python3
"""Reject lossy initialization patterns in production secret-storage code."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


DISCARDED_TRY = re.compile(
    r"\blet\s+_\s*=\s*(?:(?!;)[\s\S]){0,1024}?"
    r"(?:\.|::)\s*try_[A-Za-z_][A-Za-z0-9_]*\s*\("
)
LOSSY_ALLOCATE = re.compile(r"\.\s*allocate\s*\(")
SKIPPED_DIRECTORIES = {".git", "target", "vendor"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "reject discarded try_* results and calls to the lossy SecretPool "
            "allocate() compatibility shape"
        )
    )
    parser.add_argument(
        "--root",
        action="append",
        required=True,
        type=Path,
        help="production Rust file or directory to scan (repeatable)",
    )
    parser.add_argument(
        "--exclude-file",
        action="append",
        default=[],
        type=Path,
        help="test or generated source excluded from this production gate",
    )
    return parser.parse_args()


def normalized(path: Path) -> Path:
    return path.resolve()


def rust_files(roots: list[Path], excluded: set[Path]) -> list[Path]:
    found: set[Path] = set()
    for root in roots:
        if not root.exists():
            raise ValueError(f"scan root does not exist: {root}")
        if root.is_file():
            path = normalized(root)
            if root.suffix != ".rs":
                raise ValueError(f"scan root is not a Rust source: {root}")
            if path not in excluded:
                found.add(path)
            continue
        for path in root.rglob("*.rs"):
            if any(part in SKIPPED_DIRECTORIES for part in path.parts):
                continue
            path = normalized(path)
            if path not in excluded:
                found.add(path)
    return sorted(found)


def strip_comments_and_literals(source: str) -> str:
    output = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if output[offset] != "\n":
                output[offset] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = length if end == -1 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            blank(index, cursor)
            index = cursor
            continue
        raw = re.match(r"r(#+)?\"", source[index:])
        if raw:
            hashes = raw.group(1) or ""
            terminator = '"' + hashes
            start_content = index + raw.end()
            end = source.find(terminator, start_content)
            end = length if end == -1 else end + len(terminator)
            blank(index, end)
            index = end
            continue
        if source[index] == "'":
            character = re.match(r"'(?:\\.|[^\\'\n])'", source[index:])
            if character:
                end = index + character.end()
                blank(index, end)
                index = end
                continue
        if source[index] == '"':
            cursor = index + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                cursor += 1
                if source[cursor - 1] == '"':
                    break
            blank(index, min(cursor, length))
            index = cursor
            continue
        index += 1
    return "".join(output)


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def main() -> int:
    args = parse_args()
    excluded = {normalized(path) for path in args.exclude_file}
    try:
        files = rust_files(args.root, excluded)
    except ValueError as error:
        print(f"fail-closed initialization lint: {error}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for path in files:
        source = strip_comments_and_literals(path.read_text(encoding="utf-8"))
        for match in DISCARDED_TRY.finditer(source):
            failures.append(
                f"{relative(path)}:{line_number(source, match.start())}: "
                "discarding a try_* result can suppress initialization failure"
            )
        for match in LOSSY_ALLOCATE.finditer(source):
            failures.append(
                f"{relative(path)}:{line_number(source, match.start())}: "
                "lossy allocate() is forbidden; use try_allocate()"
            )

    if failures:
        for failure in failures:
            print(f"fail-closed initialization lint: {failure}", file=sys.stderr)
        return 1

    print(f"fail-closed initialization lint passed ({len(files)} Rust files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
