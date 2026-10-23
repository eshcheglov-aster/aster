#!/usr/bin/env python3
"""Append a bounded slow-test summary from one nextest JUnit report."""

import argparse
import math
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least one")
    return parsed


def positive_finite_seconds(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def markdown_cell(value: str) -> str:
    return " ".join(value.split()).replace("\\", "\\\\").replace("|", "\\|")


def github_command_value(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def summarize(
    source: Path,
    partition: str,
    limit: int,
    problem_seconds: float | None = None,
) -> tuple[str, list[tuple[float, str]]]:
    root = ET.parse(source).getroot()
    cases = []
    for case in root.iter("testcase"):
        name = case.get("name")
        if not name:
            raise ValueError("testcase is missing a name")
        class_name = case.get("classname")
        identity = f"{class_name}::{name}" if class_name else name
        duration = float(case.get("time", "0"))
        if not math.isfinite(duration) or duration < 0:
            raise ValueError(f"testcase {identity!r} has an invalid duration")
        cases.append((duration, identity))
    if not cases:
        raise ValueError("report contains no testcases")

    cases.sort(key=lambda item: (-item[0], item[1]))
    lines = [
        f"## Rust test timing — partition {markdown_cell(partition)}",
        "",
        f"- Tests recorded: {len(cases)}",
        f"- Cumulative test time: {sum(duration for duration, _ in cases):.3f}s",
        "",
        f"Top {min(limit, len(cases))} slowest tests:",
        "",
        "| Rank | Test | Seconds |",
        "| ---: | --- | ---: |",
    ]
    for rank, (duration, identity) in enumerate(cases[:limit], start=1):
        lines.append(f"| {rank} | {markdown_cell(identity)} | {duration:.3f} |")
    lines.append("")

    problems = []
    if problem_seconds is not None:
        problems = [item for item in cases if item[0] > problem_seconds]
        if problems:
            lines.extend(
                [
                    f"### Duration problems (> {problem_seconds:.3f}s)",
                    "",
                    "These are advisory optimization targets; they do not fail this job.",
                    "",
                    "| Test | Seconds | Target |",
                    "| --- | ---: | ---: |",
                ]
            )
            for duration, identity in problems:
                lines.append(
                    f"| {markdown_cell(identity)} | {duration:.3f} | "
                    f"{problem_seconds:.3f} |"
                )
            lines.append("")
    return "\n".join(lines), problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--partition", required=True)
    parser.add_argument("--limit", type=positive_integer, default=20)
    parser.add_argument("--problem-seconds", type=positive_finite_seconds)
    parser.add_argument("--github-annotations", action="store_true")
    arguments = parser.parse_args()

    try:
        summary, problems = summarize(
            arguments.input,
            arguments.partition,
            arguments.limit,
            arguments.problem_seconds,
        )
        with arguments.output.open("a", encoding="utf-8") as output:
            output.write(summary)
        if arguments.github_annotations and arguments.problem_seconds is not None:
            for duration, identity in problems:
                message = (
                    f"{identity} took {duration:.3f}s; advisory target "
                    f"{arguments.problem_seconds:.3f}s in partition {arguments.partition}"
                )
                print(
                    "::warning title=Rust test duration::"
                    f"{github_command_value(message)}"
                )
    except (OSError, ET.ParseError, ValueError) as error:
        print(f"nextest timing summary failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
