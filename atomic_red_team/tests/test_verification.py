from pathlib import Path

from atomic_red_team.verification import (
    build_platform_matrix,
    merge_verification_results,
    seed_allowed_atomics,
    targets_for_platform,
)


def write_atomic(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_seed_allowed_atomics_excludes_unsafe_tests(tmp_path):
    write_atomic(
        tmp_path / "T1000" / "T1000.yaml",
        """
attack_technique: T1000
display_name: Safe Examples
atomic_tests:
- name: safe command
  auto_generated_guid: 11111111-1111-4111-8111-111111111111
  description: Runs locally and cleans up.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: echo safe > /tmp/art-safe
    cleanup_command: rm /tmp/art-safe
- name: manual test
  auto_generated_guid: 22222222-2222-4222-8222-222222222222
  description: Requires a person.
  supported_platforms:
  - linux
  executor:
    name: manual
    steps: Do this by hand.
- name: elevated test
  auto_generated_guid: 33333333-3333-4333-8333-333333333333
  description: Requires elevation.
  supported_platforms:
  - linux
  executor:
    name: sh
    elevation_required: true
    command: sudo id
    cleanup_command: echo done
- name: url test
  auto_generated_guid: 44444444-4444-4444-8444-444444444444
  description: Downloads remote code.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: curl https://example.test/payload.sh
    cleanup_command: echo done
- name: url argument test
  auto_generated_guid: 88888888-8888-4888-8888-888888888888
  description: Uses a URL through an input argument.
  supported_platforms:
  - linux
  input_arguments:
    destination:
      description: Remote destination.
      type: url
      default: https://example.test/upload
  executor:
    name: sh
    command: curl #{destination}
    cleanup_command: echo done
- name: missing cleanup
  auto_generated_guid: 55555555-5555-4555-8555-555555555555
  description: Leaves state behind.
  supported_platforms:
  - linux
  executor:
    name: sh
    command: touch /tmp/art-leftover
- name: cloud test
  auto_generated_guid: 66666666-6666-4666-8666-666666666666
  description: Requires a cloud tenant.
  supported_platforms:
  - iaas:aws
  executor:
    name: sh
    command: echo aws
    cleanup_command: echo done
- name: likely interactive
  auto_generated_guid: 77777777-7777-4777-8777-777777777777
  description: Opens a UI.
  supported_platforms:
  - macos
  executor:
    name: sh
    command: osascript -e 'display dialog "hi"'
    cleanup_command: echo done
""",
    )

    allowed = seed_allowed_atomics(tmp_path)

    assert allowed["atomics"] == [
        {
            "guid": "11111111-1111-4111-8111-111111111111",
            "technique": "T1000",
            "platforms": ["linux"],
        }
    ]


def test_seed_allowed_atomics_uses_guid_as_stable_key_when_order_changes(tmp_path):
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
    first = seed_allowed_atomics(tmp_path)

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
    second = seed_allowed_atomics(tmp_path)
    second_targets = targets_for_platform(second, "linux", tmp_path)

    assert {item["guid"] for item in first["atomics"]} == {
        item["guid"] for item in second["atomics"]
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


def test_build_platform_matrix_uses_github_hosted_runners():
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
        ],
    }

    matrix = build_platform_matrix(allowed)

    assert matrix == {
        "include": [
            {"platform": "linux", "runner": "ubuntu-latest"},
            {"platform": "windows", "runner": "windows-latest"},
        ]
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
