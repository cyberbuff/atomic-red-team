from pathlib import Path

from atomic_red_team.verification import (
    build_platform_matrix,
    merge_verification_results,
    shard_for_guid,
    targets_for_platform,
)


def write_atomic(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_targets_for_platform_uses_guid_as_stable_key_when_order_changes(tmp_path):
    write_atomic(
        tmp_path / "T1001" / "T1001.yaml",
        """
attack_technique: T1001
display_name: Reordered Examples
atomic_tests:
- name: first safe command
  auto_generated_guid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo first
    cleanup_command: echo clean
- name: second safe command
  auto_generated_guid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo second
    cleanup_command: echo clean
""",
    )
    allowed = {
        "version": 1,
        "atomics": [
            {
                "guid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "technique": "T1001",
                "platforms": ["linux"],
            },
            {
                "guid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "technique": "T1001",
                "platforms": ["linux"],
            },
        ],
    }
    first_targets = targets_for_platform(allowed, "linux", tmp_path)

    write_atomic(
        tmp_path / "T1001" / "T1001.yaml",
        """
attack_technique: T1001
display_name: Reordered Examples
atomic_tests:
- name: second safe command
  auto_generated_guid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo second
    cleanup_command: echo clean
- name: first safe command
  auto_generated_guid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo first
    cleanup_command: echo clean
""",
    )
    second_targets = targets_for_platform(allowed, "linux", tmp_path)

    assert {item["guid"] for item in first_targets["atomics"]} == {
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }
    assert {item["guid"] for item in second_targets["atomics"]} == {
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    }
    assert {
        item["guid"]: item["test_number"] for item in second_targets["atomics"]
    } == {
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb": 1,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa": 2,
    }


def test_build_platform_matrix_uses_platform_shard_counts():
    allowed = {
        "version": 1,
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "technique": "T1000",
                "platforms": ["linux"],
            },
            {
                "guid": "22222222-2222-4222-8222-222222222222",
                "technique": "T1001",
                "platforms": ["windows"],
            },
            {
                "guid": "33333333-3333-4333-8333-333333333333",
                "technique": "T1002",
                "platforms": ["macos"],
            },
        ],
    }

    matrix = build_platform_matrix(
        allowed,
        shard_counts={"linux": 15, "macos": 10, "windows": 20},
    )

    assert matrix["include"] == [
        {
            "platform": "linux",
            "runner": "ubuntu-latest",
            "shard_index": shard_for_guid(
                "11111111-1111-4111-8111-111111111111",
                15,
            ),
            "shard_count": 15,
        },
        {
            "platform": "macos",
            "runner": "macos-latest",
            "shard_index": shard_for_guid(
                "33333333-3333-4333-8333-333333333333",
                10,
            ),
            "shard_count": 10,
        },
        {
            "platform": "windows",
            "runner": "windows-latest",
            "shard_index": shard_for_guid(
                "22222222-2222-4222-8222-222222222222",
                20,
            ),
            "shard_count": 20,
        },
    ]


def test_targets_for_platform_filters_to_requested_shard(tmp_path):
    write_atomic(
        tmp_path / "T1002" / "T1002.yaml",
        """
attack_technique: T1002
display_name: Sharded Examples
atomic_tests:
- name: first safe command
  auto_generated_guid: 11111111-1111-4111-8111-111111111111
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo first
    cleanup_command: echo clean
- name: second safe command
  auto_generated_guid: 22222222-2222-4222-8222-222222222222
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo second
    cleanup_command: echo clean
""",
    )
    allowed = {
        "version": 1,
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "technique": "T1002",
                "platforms": ["linux"],
            },
            {
                "guid": "22222222-2222-4222-8222-222222222222",
                "technique": "T1002",
                "platforms": ["linux"],
            },
        ],
    }

    shard_index = shard_for_guid("11111111-1111-4111-8111-111111111111", 2)
    targets = targets_for_platform(
        allowed,
        "linux",
        tmp_path,
        shard_index=shard_index,
        shard_count=2,
    )

    assert targets["shard_index"] == shard_index
    assert targets["shard_count"] == 2
    assert {atomic["guid"] for atomic in targets["atomics"]} == {
        atomic["guid"]
        for atomic in allowed["atomics"]
        if shard_for_guid(atomic["guid"], 2) == shard_index
    }


def test_merge_results_applies_failure_grace_period():
    allowed = {
        "version": 1,
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "technique": "T1000",
                "platforms": ["linux"],
            }
        ],
    }
    verified = {
        "version": 1,
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "atomic_id": "T1000-1",
                "name": "safe command",
                "verified_platforms": [
                    {
                        "platform": "linux",
                        "verified_at": "2026-05-01T09:00:00Z",
                        "run_id": "1",
                    }
                ],
            }
        ],
    }
    state = {"version": 1, "atomics": []}

    verified, state = merge_verification_results(
        allowed,
        verified,
        state,
        [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platform": "linux",
                "status": "failed",
                "atomic_id": "T1000-1",
                "name": "safe command",
                "verified_at": "2026-05-08T09:00:00Z",
                "run_id": "2",
                "error": "execution failed",
            }
        ],
    )

    assert verified["atomics"][0]["verified_platforms"][0]["platform"] == "linux"
    assert state["atomics"][0]["platforms"]["linux"]["consecutive_failures"] == 1

    verified, state = merge_verification_results(
        allowed,
        verified,
        state,
        [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platform": "linux",
                "status": "failed",
                "atomic_id": "T1000-1",
                "name": "safe command",
                "verified_at": "2026-05-15T09:00:00Z",
                "run_id": "3",
                "error": "execution failed again",
            }
        ],
    )

    assert verified["atomics"] == []
    assert state["atomics"][0]["platforms"]["linux"]["consecutive_failures"] == 2

    verified, state = merge_verification_results(
        allowed,
        verified,
        state,
        [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platform": "linux",
                "status": "passed",
                "atomic_id": "T1000-1",
                "name": "safe command",
                "verified_at": "2026-05-22T09:00:00Z",
                "run_id": "4",
            }
        ],
    )

    assert verified["atomics"][0]["verified_platforms"] == [
        {
            "platform": "linux",
            "verified_at": "2026-05-22T09:00:00Z",
            "run_id": "4",
        }
    ]
    assert state["atomics"][0]["platforms"]["linux"]["consecutive_failures"] == 0
