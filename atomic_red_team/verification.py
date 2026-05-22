import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from atomic_red_team.common import atomics_path

HOSTED_PLATFORMS = {"linux", "macos", "windows"}
RUNNERS_BY_PLATFORM = {
    "linux": "ubuntu-latest",
    "macos": "macos-latest",
    "windows": "windows-latest",
}
EXTERNAL_CONTEXT_PLATFORMS = {
    "azure-ad",
    "containers",
    "esxi",
    "google-workspace",
    "iaas",
    "iaas:aws",
    "iaas:azure",
    "iaas:gcp",
    "office-365",
    "saas",
}
INTERACTIVE_PATTERN = re.compile(
    r"SendKeys|osascript|MessageBox|notepad|Start-Process|open\s+",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(data, file, sort_keys=False)


def seed_allowed_atomics(atomics_dir: Path) -> dict[str, Any]:
    atomics = []
    for file in sorted(atomics_dir.glob("T*/T*.yaml")):
        data = read_yaml(file)
        technique = data.get("attack_technique")
        if not isinstance(technique, str):
            continue
        tests = data.get("atomic_tests", [])
        if not isinstance(tests, list):
            continue
        for test in tests:
            if not isinstance(test, dict):
                continue
            if is_hosted_safe_atomic(test):
                atomics.append(allowed_atomic_entry(technique, test))
    return {"version": 1, "atomics": atomics}


def is_hosted_safe_atomic(test: dict[str, Any]) -> bool:
    executor = test.get("executor", {})
    if not isinstance(executor, dict):
        return False
    executor_name = executor.get("name")
    if executor_name == "manual":
        return False
    platforms = test.get("supported_platforms", [])
    if not isinstance(platforms, list):
        return False
    if not any(platform in HOSTED_PLATFORMS for platform in platforms):
        return False
    if any(platform in EXTERNAL_CONTEXT_PLATFORMS for platform in platforms):
        return False
    if executor.get("elevation_required") is True:
        return False
    if "cleanup_command" not in executor:
        return False
    command_text = collect_command_text(test)
    if URL_PATTERN.search(command_text):
        return False
    if INTERACTIVE_PATTERN.search(command_text):
        return False
    return True


def collect_command_text(test: dict[str, Any]) -> str:
    executor = test.get("executor", {})
    commands = []
    if isinstance(executor, dict):
        commands.extend([executor.get("command"), executor.get("cleanup_command")])
    dependencies = test.get("dependencies") or []
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if isinstance(dependency, dict):
                commands.extend(
                    [
                        dependency.get("prereq_command"),
                        dependency.get("get_prereq_command"),
                    ]
                )
    input_arguments = test.get("input_arguments") or {}
    if isinstance(input_arguments, dict):
        for argument in input_arguments.values():
            if isinstance(argument, dict):
                commands.append(argument.get("default"))
    return "\n".join(command for command in commands if isinstance(command, str))


def allowed_atomic_entry(technique: str, test: dict[str, Any]) -> dict[str, Any]:
    platforms = [
        platform
        for platform in test.get("supported_platforms", [])
        if platform in HOSTED_PLATFORMS
    ]
    return {
        "guid": str(test["auto_generated_guid"]),
        "technique": technique,
        "platforms": sorted(platforms),
    }


def build_platform_matrix(allowed: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    platforms = set()
    for atomic in allowed.get("atomics", []):
        if isinstance(atomic, dict):
            platforms.update(atomic.get("platforms", []))
    include = [
        {"platform": platform, "runner": RUNNERS_BY_PLATFORM[platform]}
        for platform in sorted(platforms)
        if platform in RUNNERS_BY_PLATFORM
    ]
    return {"include": include}


def targets_for_platform(
    allowed: dict[str, Any],
    platform: str,
    atomics_dir: Path = Path(atomics_path),
) -> dict[str, Any]:
    atomics = []
    for atomic in allowed.get("atomics", []):
        if isinstance(atomic, dict) and platform in atomic.get("platforms", []):
            resolved = resolve_atomic_target(
                atomics_dir,
                atomic["technique"],
                atomic["guid"],
            )
            resolved["platform"] = platform
            atomics.append(resolved)
    return {"version": 1, "platform": platform, "atomics": atomics}


def resolve_atomic_target(
    atomics_dir: Path,
    technique: str,
    guid: str,
) -> dict[str, Any]:
    path = atomics_dir / technique / f"{technique}.yaml"
    data = read_yaml(path)
    tests = data.get("atomic_tests", [])
    if not isinstance(tests, list):
        raise ValueError(f"{path} must contain an atomic_tests list")
    for index, test in enumerate(tests, start=1):
        if not isinstance(test, dict):
            continue
        if str(test.get("auto_generated_guid")) == guid:
            return {
                "guid": guid,
                "atomic_id": f"{technique}-{index}",
                "technique": technique,
                "test_number": index,
                "name": str(test["name"]),
            }
    raise ValueError(f"GUID {guid} is not present in {path}")


def merge_verification_results(
    allowed: dict[str, Any],
    verified: dict[str, Any],
    state: dict[str, Any],
    results: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    allowed_by_guid = {
        atomic["guid"]: atomic
        for atomic in allowed.get("atomics", [])
        if isinstance(atomic, dict) and "guid" in atomic
    }
    verified_by_guid = index_verified(verified)
    state_by_guid = index_state(state)

    for result in results:
        guid = result["guid"]
        platform = result["platform"]
        if guid not in allowed_by_guid:
            continue
        current_state = state_by_guid.setdefault(guid, {"guid": guid, "platforms": {}})
        platform_state = current_state["platforms"].setdefault(
            platform,
            {"consecutive_failures": 0},
        )
        if result["status"] == "passed":
            platform_state.update(
                {
                    "consecutive_failures": 0,
                    "last_status": "passed",
                    "last_run_at": result.get("verified_at"),
                    "last_run_id": result.get("run_id"),
                }
            )
            platform_state.pop("last_error", None)
            add_verified_platform(verified_by_guid, result)
        else:
            failures = int(platform_state.get("consecutive_failures", 0)) + 1
            platform_state.update(
                {
                    "consecutive_failures": failures,
                    "last_status": "failed",
                    "last_run_at": result.get("verified_at"),
                    "last_run_id": result.get("run_id"),
                    "last_error": result.get("error", ""),
                }
            )
            if failures >= 2:
                remove_verified_platform(verified_by_guid, guid, platform)

    verified_data = {
        "version": 1,
        "atomics": sorted(
            [
                atomic
                for atomic in verified_by_guid.values()
                if atomic.get("verified_platforms")
            ],
            key=lambda atomic: atomic["atomic_id"],
        ),
    }
    state_data = {
        "version": 1,
        "atomics": sorted(state_by_guid.values(), key=lambda atomic: atomic["guid"]),
    }
    return verified_data, state_data


def index_verified(verified: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for atomic in verified.get("atomics", []):
        if isinstance(atomic, dict) and atomic.get("guid"):
            indexed[atomic["guid"]] = {
                "guid": atomic["guid"],
                "atomic_id": atomic["atomic_id"],
                "name": atomic["name"],
                "verified_platforms": list(atomic.get("verified_platforms", [])),
            }
    return indexed


def index_state(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for atomic in state.get("atomics", []):
        if isinstance(atomic, dict) and atomic.get("guid"):
            indexed[atomic["guid"]] = {
                "guid": atomic["guid"],
                "platforms": dict(atomic.get("platforms", {})),
            }
    return indexed


def add_verified_platform(
    verified_by_guid: dict[str, dict[str, Any]],
    result: dict[str, Any],
) -> None:
    entry = verified_by_guid.setdefault(
        result["guid"],
        {
            "guid": result["guid"],
            "atomic_id": result["atomic_id"],
            "name": result["name"],
            "verified_platforms": [],
        },
    )
    entry["atomic_id"] = result["atomic_id"]
    entry["name"] = result["name"]
    platforms = [
        item
        for item in entry["verified_platforms"]
        if item.get("platform") != result["platform"]
    ]
    platforms.append(
        {
            "platform": result["platform"],
            "verified_at": result.get("verified_at"),
            "run_id": result.get("run_id"),
        }
    )
    entry["verified_platforms"] = sorted(
        platforms,
        key=lambda item: item["platform"],
    )


def remove_verified_platform(
    verified_by_guid: dict[str, dict[str, Any]],
    guid: str,
    platform: str,
) -> None:
    if guid not in verified_by_guid:
        return
    verified_by_guid[guid]["verified_platforms"] = [
        item
        for item in verified_by_guid[guid].get("verified_platforms", [])
        if item.get("platform") != platform
    ]


def load_results(results_dir: Path) -> list[dict[str, Any]]:
    results = []
    for path in sorted(results_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict) and isinstance(data.get("results"), list):
            results.extend(data["results"])
        else:
            raise ValueError(f"{path} must contain a results array")
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Atomic verification helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    seed = subparsers.add_parser("seed-allowed")
    seed.add_argument("--atomics-dir", default=atomics_path)
    seed.add_argument("--output", default="verification/allowed-atomics.yaml")

    matrix = subparsers.add_parser("build-matrix")
    matrix.add_argument("--allowed", default="verification/allowed-atomics.yaml")
    matrix.add_argument("--output", default="-")

    targets = subparsers.add_parser("targets")
    targets.add_argument("--allowed", default="verification/allowed-atomics.yaml")
    targets.add_argument("--platform", required=True)
    targets.add_argument("--output", required=True)

    merge = subparsers.add_parser("merge-results")
    merge.add_argument("--allowed", default="verification/allowed-atomics.yaml")
    merge.add_argument("--verified", default="verification/verified-atomics.yaml")
    merge.add_argument("--state", default="verification/verification-state.yaml")
    merge.add_argument("--results-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "seed-allowed":
        data = seed_allowed_atomics(Path(args.atomics_dir))
        write_yaml(Path(args.output), data)
        return 0
    if args.command == "build-matrix":
        data = build_platform_matrix(read_yaml(Path(args.allowed)))
        text = json.dumps(data, separators=(",", ":"))
        if args.output == "-":
            print(text)
        else:
            Path(args.output).write_text(text, encoding="utf-8")
        return 0
    if args.command == "targets":
        data = targets_for_platform(read_yaml(Path(args.allowed)), args.platform)
        Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return 0
    if args.command == "merge-results":
        verified, state = merge_verification_results(
            read_yaml(Path(args.allowed)),
            read_yaml(Path(args.verified)),
            read_yaml(Path(args.state)),
            load_results(Path(args.results_dir)),
        )
        write_yaml(Path(args.verified), verified)
        write_yaml(Path(args.state), state)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
