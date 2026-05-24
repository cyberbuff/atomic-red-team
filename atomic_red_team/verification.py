import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from atomic_red_team.common import atomics_path

DEFAULT_PLATFORM_SHARD_COUNTS = {
    "linux": 15,
    "macos": 10,
    "windows": 20,
}
RUNNERS_BY_PLATFORM = {
    "linux": "ubuntu-latest",
    "macos": "macos-latest",
    "windows": "windows-latest",
}
STATE_METADATA_FILE = "metadata.json"
MAX_STATE_STREAM_CHARS = 60_000


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


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")


def compact_output_stream(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    if len(value) <= MAX_STATE_STREAM_CHARS:
        return value

    marker = (
        "\n\n"
        f"[verification output truncated: {len(value) - MAX_STATE_STREAM_CHARS} "
        "characters omitted]"
        "\n\n"
    )
    head_length = (MAX_STATE_STREAM_CHARS - len(marker)) // 2
    tail_length = MAX_STATE_STREAM_CHARS - len(marker) - head_length
    return f"{value[:head_length]}{marker}{value[-tail_length:]}"


def result_exit_code(result: dict[str, Any]) -> int:
    try:
        return int(result.get("exit_code", 0))
    except (TypeError, ValueError):
        return 1


def result_stderr(result: dict[str, Any]) -> str:
    return compact_output_stream(result.get("stderr", ""))


def result_passed_cleanly(result: dict[str, Any]) -> bool:
    return (
        result.get("status") == "passed"
        and result_exit_code(result) == 0
        and result_stderr(result) == ""
    )


def verification_error(result: dict[str, Any]) -> str:
    if result.get("status") != "passed":
        return str(result.get("error", "verification failed"))
    exit_code = result_exit_code(result)
    if exit_code != 0:
        return f"Command exited with code {exit_code}"
    return "Command wrote to stderr"


def read_verification_state(path: Path) -> dict[str, Any]:
    if path.is_dir():
        metadata = read_json(path / STATE_METADATA_FILE)
        state = {
            "version": metadata.get("version", 2),
            "atomics": read_atomic_state_files(path),
        }
        if "last_run_time" in metadata:
            state["last_run_at"] = metadata["last_run_time"]
        elif "last_run_at" in metadata:
            state["last_run_at"] = metadata["last_run_at"]
        if "last_run_id" in metadata:
            state["last_run_id"] = metadata["last_run_id"]
        return state
    if path.exists():
        return read_yaml(path)
    legacy_path = path.with_suffix(".yaml")
    if legacy_path.exists():
        return read_yaml(legacy_path)
    return {}


def read_atomic_state_files(path: Path) -> list[dict[str, Any]]:
    atomics = []
    for atomic_path in sorted(path.glob("*.json")):
        if atomic_path.name == STATE_METADATA_FILE:
            continue
        data = read_json(atomic_path)
        if data:
            atomics.append(data)
    return sorted(atomics, key=lambda atomic: atomic.get("guid", ""))


def write_verification_state(path: Path, state: dict[str, Any]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    metadata = {"version": state.get("version", 2)}
    if "last_run_at" in state:
        metadata["last_run_time"] = state["last_run_at"]
    if "last_run_id" in state:
        metadata["last_run_id"] = state["last_run_id"]
    write_json(path / STATE_METADATA_FILE, metadata)

    atomics = [
        atomic
        for atomic in state.get("atomics", [])
        if isinstance(atomic, dict) and isinstance(atomic.get("guid"), str)
    ]
    expected_files = {f"{atomic['guid']}.json" for atomic in atomics}
    for atomic_path in path.glob("*.json"):
        if atomic_path.name not in expected_files and atomic_path.name != STATE_METADATA_FILE:
            atomic_path.unlink()
    for atomic in sorted(atomics, key=lambda item: item["guid"]):
        write_json(path / f"{atomic['guid']}.json", atomic)


def shard_for_guid(guid: str, shard_count: int) -> int:
    if shard_count < 1:
        raise ValueError("shard_count must be at least 1")
    digest = hashlib.sha256(guid.encode("utf-8")).hexdigest()
    return int(digest, 16) % shard_count


def build_platform_matrix(
    allowed: dict[str, Any],
    shard_counts: dict[str, int] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    shard_counts = shard_counts or DEFAULT_PLATFORM_SHARD_COUNTS
    for platform, shard_count in shard_counts.items():
        if shard_count < 1:
            raise ValueError(f"{platform} shard_count must be at least 1")
    shards_by_platform: dict[str, set[int]] = {}
    for atomic in allowed.get("atomics", []):
        if not isinstance(atomic, dict):
            continue
        guid = atomic.get("guid")
        if not isinstance(guid, str):
            continue
        for platform in atomic.get("platforms", []):
            if platform in RUNNERS_BY_PLATFORM:
                shard_count = shard_counts.get(platform, 1)
                shards_by_platform.setdefault(platform, set()).add(
                    shard_for_guid(guid, shard_count)
                )
    include = []
    for platform in sorted(shards_by_platform):
        for shard_index in sorted(shards_by_platform[platform]):
            include.append(
                {
                    "platform": platform,
                    "runner": RUNNERS_BY_PLATFORM[platform],
                    "shard_index": shard_index,
                    "shard_count": shard_counts.get(platform, 1),
                }
            )
    return {"include": include}


def targets_for_platform(
    allowed: dict[str, Any],
    platform: str,
    atomics_dir: Path = Path(atomics_path),
    shard_index: int | None = None,
    shard_count: int = 1,
) -> dict[str, Any]:
    if shard_count < 1:
        raise ValueError("shard_count must be at least 1")
    if shard_index is not None and not 0 <= shard_index < shard_count:
        raise ValueError(
            "shard_index must be greater than or equal to 0 and less than shard_count"
        )
    atomics = []
    for atomic in allowed.get("atomics", []):
        if not isinstance(atomic, dict) or platform not in atomic.get("platforms", []):
            continue
        guid = atomic["guid"]
        if shard_index is not None and shard_for_guid(guid, shard_count) != shard_index:
            continue
        resolved = resolve_atomic_target(
            atomics_dir,
            atomic["technique"],
            guid,
        )
        resolved["platform"] = platform
        atomics.append(resolved)
    targets = {"version": 1, "platform": platform, "atomics": atomics}
    if shard_index is not None:
        targets["shard_index"] = shard_index
        targets["shard_count"] = shard_count
    return targets


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
        if result_passed_cleanly(result):
            platform_state.update(
                {
                    "consecutive_failures": 0,
                    "last_status": "passed",
                    "exit_code": result_exit_code(result),
                    "stdout": compact_output_stream(result.get("stdout", "")),
                    "stderr": result_stderr(result),
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
                    "last_error": verification_error(result),
                    "exit_code": result_exit_code(result),
                    "stdout": compact_output_stream(result.get("stdout", "")),
                    "stderr": result_stderr(result),
                }
            )
            remove_verified_platform(verified_by_guid, guid, platform)

    verified_data = {
        "version": 1,
        **latest_verified_metadata(verified, results),
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
        "version": 2,
        **latest_run_metadata(state, results),
        "atomics": sorted(state_by_guid.values(), key=lambda atomic: atomic["guid"]),
    }
    return verified_data, state_data


def latest_verified_metadata(
    previous_verified: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    metadata = latest_metadata_from_items(results, "verified_at", "run_id")
    if "verified_at" in metadata:
        return metadata
    if "verified_at" in previous_verified:
        metadata["verified_at"] = previous_verified["verified_at"]
    if "run_id" in previous_verified:
        metadata["run_id"] = previous_verified["run_id"]
    if "verified_at" in metadata:
        return metadata
    return latest_verified_platform_metadata(previous_verified)


def latest_verified_platform_metadata(previous_verified: dict[str, Any]) -> dict[str, Any]:
    items = []
    for atomic in previous_verified.get("atomics", []):
        if not isinstance(atomic, dict):
            continue
        verified_platforms = atomic.get("verified_platforms", [])
        if not isinstance(verified_platforms, list):
            continue
        items.extend(
            platform
            for platform in verified_platforms
            if isinstance(platform, dict)
        )
    return latest_metadata_from_items(items, "verified_at", "run_id")


def latest_metadata_from_items(
    items: list[dict[str, Any]],
    timestamp_key: str,
    run_id_key: str,
) -> dict[str, Any]:
    latest_timestamp = None
    latest_run_id = None
    for item in items:
        timestamp = item.get(timestamp_key)
        if not isinstance(timestamp, str):
            continue
        if latest_timestamp is None or timestamp > latest_timestamp:
            latest_timestamp = timestamp
            latest_run_id = item.get(run_id_key)
    metadata: dict[str, Any] = {}
    if latest_timestamp is not None:
        metadata[timestamp_key] = latest_timestamp
    if isinstance(latest_run_id, str | int):
        metadata[run_id_key] = str(latest_run_id)
    return metadata


def latest_run_metadata(
    previous_state: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    run_times = [
        str(result["verified_at"])
        for result in results
        if isinstance(result.get("verified_at"), str)
    ]
    run_ids = [
        str(result["run_id"])
        for result in results
        if isinstance(result.get("run_id"), str | int)
    ]
    metadata: dict[str, Any] = {}
    platform_metadata: dict[str, Any] = {}
    if run_times:
        metadata["last_run_at"] = max(run_times)
    elif "last_run_at" in previous_state:
        metadata["last_run_at"] = previous_state["last_run_at"]
    else:
        platform_metadata = latest_platform_run_metadata(previous_state)
        if "last_run_at" in platform_metadata:
            metadata["last_run_at"] = platform_metadata["last_run_at"]
    if run_ids:
        metadata["last_run_id"] = run_ids[0]
    elif "last_run_id" in previous_state:
        metadata["last_run_id"] = previous_state["last_run_id"]
    elif "last_run_id" in platform_metadata:
        metadata["last_run_id"] = platform_metadata["last_run_id"]
    return metadata


def latest_platform_run_metadata(previous_state: dict[str, Any]) -> dict[str, Any]:
    latest_run_at = None
    latest_run_id = None
    for atomic in previous_state.get("atomics", []):
        if not isinstance(atomic, dict):
            continue
        platforms = atomic.get("platforms", {})
        if not isinstance(platforms, dict):
            continue
        for platform_state in platforms.values():
            if not isinstance(platform_state, dict):
                continue
            last_run_at = platform_state.get("last_run_at")
            if not isinstance(last_run_at, str):
                continue
            if latest_run_at is None or last_run_at > latest_run_at:
                latest_run_at = last_run_at
                latest_run_id = platform_state.get("last_run_id")
    metadata: dict[str, Any] = {}
    if latest_run_at is not None:
        metadata["last_run_at"] = latest_run_at
    if isinstance(latest_run_id, str | int):
        metadata["last_run_id"] = str(latest_run_id)
    return metadata


def index_verified(verified: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for atomic in verified.get("atomics", []):
        if isinstance(atomic, dict) and atomic.get("guid"):
            indexed[atomic["guid"]] = {
                "guid": atomic["guid"],
                "atomic_id": atomic["atomic_id"],
                "name": atomic["name"],
                "verified_platforms": normalize_verified_platforms(
                    atomic.get("verified_platforms", [])
                ),
            }
    return indexed


def normalize_verified_platforms(verified_platforms: Any) -> list[dict[str, Any]]:
    if not isinstance(verified_platforms, list):
        return []
    platforms = []
    for item in verified_platforms:
        if isinstance(item, dict) and isinstance(item.get("platform"), str):
            platforms.append({"platform": item["platform"]})
    return platforms


def index_state(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for atomic in state.get("atomics", []):
        if isinstance(atomic, dict) and atomic.get("guid"):
            platforms = atomic.get("platforms", {})
            if not isinstance(platforms, dict):
                platforms = {}
            indexed[atomic["guid"]] = {
                "guid": atomic["guid"],
                "platforms": {
                    platform: normalize_platform_state(platform_state)
                    for platform, platform_state in platforms.items()
                    if isinstance(platform_state, dict)
                },
            }
    return indexed


def normalize_platform_state(platform_state: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(platform_state)
    normalized.pop("last_run_at", None)
    normalized.pop("last_run_id", None)
    normalized.setdefault("exit_code", 0)
    normalized["stdout"] = compact_output_stream(normalized.get("stdout", ""))
    normalized["stderr"] = compact_output_stream(normalized.get("stderr", ""))
    return normalized


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
        {"platform": result["platform"]}
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

    matrix = subparsers.add_parser("build-matrix")
    matrix.add_argument("--allowed", default="verification/allowed-atomics.yaml")
    matrix.add_argument("--output", default="-")
    matrix.add_argument(
        "--linux-shard-count",
        type=int,
        default=DEFAULT_PLATFORM_SHARD_COUNTS["linux"],
    )
    matrix.add_argument(
        "--macos-shard-count",
        type=int,
        default=DEFAULT_PLATFORM_SHARD_COUNTS["macos"],
    )
    matrix.add_argument(
        "--windows-shard-count",
        type=int,
        default=DEFAULT_PLATFORM_SHARD_COUNTS["windows"],
    )

    targets = subparsers.add_parser("targets")
    targets.add_argument("--allowed", default="verification/allowed-atomics.yaml")
    targets.add_argument("--platform", required=True)
    targets.add_argument("--output", required=True)
    targets.add_argument("--shard-index", type=int)
    targets.add_argument("--shard-count", type=int, default=1)

    merge = subparsers.add_parser("merge-results")
    merge.add_argument("--allowed", default="verification/allowed-atomics.yaml")
    merge.add_argument("--verified", default="verification/verified-atomics.yaml")
    merge.add_argument("--state", default="verification/verification-state")
    merge.add_argument("--results-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "build-matrix":
        data = build_platform_matrix(
            read_yaml(Path(args.allowed)),
            shard_counts={
                "linux": args.linux_shard_count,
                "macos": args.macos_shard_count,
                "windows": args.windows_shard_count,
            },
        )
        text = json.dumps(data, separators=(",", ":"))
        if args.output == "-":
            print(text)
        else:
            Path(args.output).write_text(text, encoding="utf-8")
        return 0
    if args.command == "targets":
        data = targets_for_platform(
            read_yaml(Path(args.allowed)),
            args.platform,
            shard_index=args.shard_index,
            shard_count=args.shard_count,
        )
        Path(args.output).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return 0
    if args.command == "merge-results":
        verified, state = merge_verification_results(
            read_yaml(Path(args.allowed)),
            read_yaml(Path(args.verified)),
            read_verification_state(Path(args.state)),
            load_results(Path(args.results_dir)),
        )
        write_yaml(Path(args.verified), verified)
        write_verification_state(Path(args.state), state)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
