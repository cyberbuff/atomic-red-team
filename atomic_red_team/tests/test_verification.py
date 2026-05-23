from pathlib import Path

from atomic_red_team.verification import (
    build_platform_matrix,
    merge_verification_results,
    read_verification_state,
    shard_for_guid,
    targets_for_platform,
    write_verification_state,
)

RUNNER_SCRIPT = Path("verification/run-atomic-verification.ps1")


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

    assert verified["verified_at"] == "2026-05-22T09:00:00Z"
    assert verified["run_id"] == "4"
    assert verified["atomics"][0]["verified_platforms"] == [
        {"platform": "linux"}
    ]
    assert state["atomics"][0]["platforms"]["linux"]["consecutive_failures"] == 0


def test_merge_results_promotes_verified_platform_metadata_to_root():
    allowed = {"version": 1, "atomics": []}
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
                        "verified_at": "2026-05-15T09:00:00Z",
                        "run_id": "3",
                    },
                    {
                        "platform": "macos",
                        "verified_at": "2026-05-22T09:00:00Z",
                        "run_id": "4",
                    },
                ],
            }
        ],
    }
    state = {"version": 1, "atomics": []}

    verified, _ = merge_verification_results(allowed, verified, state, [])

    assert verified["verified_at"] == "2026-05-22T09:00:00Z"
    assert verified["run_id"] == "4"
    assert verified["atomics"][0]["verified_platforms"] == [
        {"platform": "linux"},
        {"platform": "macos"},
    ]


def test_merge_results_writes_run_metadata_and_output_to_state():
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
    verified = {"version": 1, "atomics": []}
    state = {"version": 1, "atomics": []}

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
                "exit_code": 0,
                "stdout": "command output\n",
                "stderr": "warning output\n",
            }
        ],
    )

    assert verified["version"] == 1
    assert state["version"] == 2
    assert state["last_run_at"] == "2026-05-22T09:00:00Z"
    assert state["last_run_id"] == "4"
    platform_state = state["atomics"][0]["platforms"]["linux"]
    assert platform_state == {
        "consecutive_failures": 0,
        "last_status": "passed",
        "exit_code": 0,
        "stdout": "command output\n",
        "stderr": "warning output\n",
    }


def test_merge_results_removes_platform_run_metadata_from_existing_state():
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
    verified = {"version": 1, "atomics": []}
    state = {
        "version": 1,
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platforms": {
                    "linux": {
                        "consecutive_failures": 1,
                        "last_status": "failed",
                        "last_run_at": "2026-05-15T09:00:00Z",
                        "last_run_id": "3",
                        "last_error": "old failure",
                    }
                },
            }
        ],
    }

    _, state = merge_verification_results(
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
                "verified_at": "2026-05-22T09:00:00Z",
                "run_id": "4",
                "error": "new failure",
                "exit_code": 7,
                "stdout": "",
                "stderr": "new stderr",
            }
        ],
    )

    platform_state = state["atomics"][0]["platforms"]["linux"]
    assert "last_run_at" not in platform_state
    assert "last_run_id" not in platform_state
    assert platform_state["last_error"] == "new failure"
    assert platform_state["exit_code"] == 7
    assert platform_state["stdout"] == ""
    assert platform_state["stderr"] == "new stderr"


def test_merge_results_promotes_existing_platform_run_metadata_when_no_results():
    allowed = {"version": 1, "atomics": []}
    verified = {"version": 1, "atomics": []}
    state = {
        "version": 1,
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platforms": {
                    "linux": {
                        "consecutive_failures": 0,
                        "last_status": "passed",
                        "last_run_at": "2026-05-15T09:00:00Z",
                        "last_run_id": "3",
                    },
                    "macos": {
                        "consecutive_failures": 0,
                        "last_status": "passed",
                        "last_run_at": "2026-05-22T09:00:00Z",
                        "last_run_id": "4",
                    },
                },
            }
        ],
    }

    _, state = merge_verification_results(allowed, verified, state, [])

    assert state["last_run_at"] == "2026-05-22T09:00:00Z"
    assert state["last_run_id"] == "4"
    platform_state = state["atomics"][0]["platforms"]["macos"]
    assert "last_run_at" not in platform_state
    assert "last_run_id" not in platform_state
    assert platform_state["exit_code"] == 0


def test_write_verification_state_splits_metadata_and_atomic_files(tmp_path):
    state_dir = tmp_path / "verification-state"
    state = {
        "version": 2,
        "last_run_at": "2026-05-22T09:00:00Z",
        "last_run_id": "4",
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platforms": {
                    "linux": {
                        "consecutive_failures": 0,
                        "last_status": "passed",
                        "exit_code": 0,
                        "stdout": "command output\n",
                        "stderr": "",
                    }
                },
            }
        ],
    }

    write_verification_state(state_dir, state)

    assert not (tmp_path / "verification-state.yaml").exists()
    assert (state_dir / "metadata.json").read_text(encoding="utf-8") == (
        '{\n'
        '  "version": 2,\n'
        '  "last_run_time": "2026-05-22T09:00:00Z",\n'
        '  "last_run_id": "4"\n'
        '}\n'
    )
    assert (state_dir / "11111111-1111-4111-8111-111111111111.json").exists()


def test_read_verification_state_loads_directory_files(tmp_path):
    state_dir = tmp_path / "verification-state"
    state_dir.mkdir()
    (state_dir / "metadata.json").write_text(
        '{\n'
        '  "version": 2,\n'
        '  "last_run_time": "2026-05-22T09:00:00Z",\n'
        '  "last_run_id": "4"\n'
        '}\n',
        encoding="utf-8",
    )
    (state_dir / "11111111-1111-4111-8111-111111111111.json").write_text(
        '{\n'
        '  "guid": "11111111-1111-4111-8111-111111111111",\n'
        '  "platforms": {\n'
        '    "linux": {\n'
        '      "consecutive_failures": 0,\n'
        '      "last_status": "passed",\n'
        '      "exit_code": 0,\n'
        '      "stdout": "command output\\n",\n'
        '      "stderr": ""\n'
        '    }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )

    state = read_verification_state(state_dir)

    assert state == {
        "version": 2,
        "last_run_at": "2026-05-22T09:00:00Z",
        "last_run_id": "4",
        "atomics": [
            {
                "guid": "11111111-1111-4111-8111-111111111111",
                "platforms": {
                    "linux": {
                        "consecutive_failures": 0,
                        "last_status": "passed",
                        "exit_code": 0,
                        "stdout": "command output\n",
                        "stderr": "",
                    }
                },
            }
        ],
    }


def test_runner_captures_stage_output_and_emits_result_streams():
    script = RUNNER_SCRIPT.read_text(encoding="utf-8")

    assert "& $ScriptBlock *> $null" not in script
    assert "stdout = Get-JoinedFileText -Paths $stdoutPaths" in script
    assert "stderr = Get-FileText -Path $stderrPath" in script
    assert "stdout = $stdout" in script
    assert "stderr = $stderr" in script


def test_runner_calculates_stage_status_from_exit_code():
    script = RUNNER_SCRIPT.read_text(encoding="utf-8")

    assert "$LASTEXITCODE = 0" in script
    assert "$stageExitCode = [int]$LASTEXITCODE" in script
    assert "if ($stageExitCode -eq 0)" in script
    assert "Command exited with code $stageExitCode" in script


def test_runner_fails_stage_when_inner_command_logs_nonzero_exit_code():
    script = RUNNER_SCRIPT.read_text(encoding="utf-8")

    assert "function Get-InnerExitCode" in script
    assert "Exit code:\\s*(\\d+)" in script
    assert "$innerExitCode = Get-InnerExitCode" in script
    assert "if ($stageExitCode -eq 0 -and $innerExitCode -ne 0)" in script


def test_runner_captures_non_error_powershell_streams_as_stdout():
    script = RUNNER_SCRIPT.read_text(encoding="utf-8")

    assert "3>> $stdoutPath" not in script
    assert "4>> $stdoutPath" not in script
    assert "5>> $stdoutPath" not in script
    assert "6>> $stdoutPath" not in script
    assert "$warningPath = [System.IO.Path]::GetTempFileName()" in script
    assert "$verbosePath = [System.IO.Path]::GetTempFileName()" in script
    assert "$debugPath = [System.IO.Path]::GetTempFileName()" in script
    assert "$informationPath = [System.IO.Path]::GetTempFileName()" in script
    assert "3> $warningPath" in script
    assert "4> $verbosePath" in script
    assert "5> $debugPath" in script
    assert "6> $informationPath" in script


def test_runner_emits_stage_and_result_exit_codes():
    script = RUNNER_SCRIPT.read_text(encoding="utf-8")

    assert "exit_code = 0" in script
    assert "exit_code = $stageExitCode" in script
    assert "$exitCode = 0" in script
    assert "$exitCode = $failedStage.exit_code" in script
    assert "exit_code = $exitCode" in script
