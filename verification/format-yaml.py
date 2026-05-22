#!/usr/bin/env python3
"""Format verification YAML files and sort atomics by GUID."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def sort_atomics(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    atomics = data.get("atomics")
    if atomics is None:
        return data
    if not isinstance(atomics, list):
        raise ValueError(f"{path} atomics must be a YAML list")
    for index, atomic in enumerate(atomics, start=1):
        if not isinstance(atomic, dict):
            raise ValueError(f"{path} atomics[{index}] must be a YAML mapping")
        if "guid" not in atomic:
            raise ValueError(f"{path} atomics[{index}] is missing guid")
    data["atomics"] = sorted(atomics, key=lambda atomic: str(atomic["guid"]))
    return data


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(data, file, sort_keys=False)


def format_directory(directory: Path) -> list[Path]:
    formatted = []
    for path in sorted(directory.glob("*.yaml")):
        data = sort_atomics(path, read_yaml(path))
        write_yaml(path, data)
        formatted.append(path)
    return formatted


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Format verification YAML files and sort atomics by GUID."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory containing verification YAML files.",
    )
    args = parser.parse_args()
    formatted = format_directory(args.directory)
    for path in formatted:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
