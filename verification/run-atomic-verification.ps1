param(
  [Parameter(Mandatory = $true)]
  [string]$TargetsPath,

  [Parameter(Mandatory = $true)]
  [string]$OutputPath,

  [string]$AtomicsPath = (Join-Path (Get-Location) "atomics"),

  [string]$InvokeAtomicVersion = "2.3.0"
)

$ErrorActionPreference = "Stop"

function Get-FileText {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  if (-not (Test-Path -Path $Path)) {
    return ""
  }
  $text = Get-Content -Raw -Path $Path
  if ($null -eq $text) {
    return ""
  }
  return $text
}

function Get-InnerExitCode {
  param(
    [string[]]$Texts
  )

  foreach ($text in $Texts) {
    foreach ($match in [regex]::Matches($text, "Exit code:\s*(\d+)")) {
      $exitCode = [int]$match.Groups[1].Value
      if ($exitCode -ne 0) {
        return $exitCode
      }
    }
  }
  return 0
}

function Add-Stage {
  param(
    [System.Collections.Generic.List[object]]$Stages,

    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [scriptblock]$ScriptBlock
  )

  $started = Get-Date
  $stdoutPath = [System.IO.Path]::GetTempFileName()
  $stderrPath = [System.IO.Path]::GetTempFileName()
  try {
    $LASTEXITCODE = 0
    & $ScriptBlock 1> $stdoutPath 2> $stderrPath 3>> $stdoutPath `
      4>> $stdoutPath 5>> $stdoutPath 6>> $stdoutPath
    $stageExitCode = [int]$LASTEXITCODE
    $stdout = Get-FileText -Path $stdoutPath
    $stderr = Get-FileText -Path $stderrPath
    $innerExitCode = Get-InnerExitCode -Texts @($stdout, $stderr)
    if ($stageExitCode -eq 0 -and $innerExitCode -ne 0) {
      $stageExitCode = $innerExitCode
    }
    if ($stageExitCode -eq 0) {
      $Stages.Add([ordered]@{
          name = $Name
          status = "passed"
          duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
          exit_code = 0
          stdout = $stdout
          stderr = $stderr
        })
      return $true
    }

    $Stages.Add([ordered]@{
        name = $Name
        status = "failed"
        duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        error = "Command exited with code $stageExitCode"
        exit_code = $stageExitCode
        stdout = $stdout
        stderr = $stderr
      })
    return $false
  }
  catch {
    $Stages.Add([ordered]@{
        name = $Name
        status = "failed"
        duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        error = $_.Exception.Message
        exit_code = 1
        stdout = Get-FileText -Path $stdoutPath
        stderr = Get-FileText -Path $stderrPath
      })
    return $false
  }
  finally {
    Remove-Item -Force -ErrorAction SilentlyContinue -Path $stdoutPath, $stderrPath
  }
}

function Invoke-AtomicStage {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Target,

    [switch]$CheckPrereqs,
    [switch]$GetPrereqs,
    [switch]$Cleanup
  )

  $arguments = @{
    PathToAtomicsFolder = $AtomicsPath
    TestNumbers = $Target.test_number
    Confirm = $false
    ErrorAction = "Stop"
  }
  if ($CheckPrereqs) {
    $arguments.CheckPrereqs = $true
  }
  if ($GetPrereqs) {
    $arguments.GetPrereqs = $true
  }
  if ($Cleanup) {
    $arguments.Cleanup = $true
  }
  Invoke-AtomicTest $Target.technique @arguments
}

function Write-AtomicProgressLog {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Platform,

    [Parameter(Mandatory = $true)]
    [object]$Target,

    [Parameter(Mandatory = $true)]
    [int]$CurrentTarget,

    [Parameter(Mandatory = $true)]
    [int]$TotalTargets,

    [Parameter(Mandatory = $true)]
    [int]$PercentComplete
  )

  $barWidth = 20
  $filledWidth = [math]::Floor(($PercentComplete / 100) * $barWidth)
  $emptyWidth = $barWidth - $filledWidth
  $bar = ("#" * $filledWidth) + ("-" * $emptyWidth)
  Write-Host "[$bar] $PercentComplete% ($CurrentTarget/$TotalTargets) " `
    "$Platform $($Target.atomic_id) - $($Target.name)"
}

$targetsDocument = Get-Content -Raw -Path $TargetsPath | ConvertFrom-Json
$results = [System.Collections.Generic.List[object]]::new()
$runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }

Install-Module `
  -Name Invoke-AtomicRedTeam `
  -RequiredVersion $InvokeAtomicVersion `
  -Scope CurrentUser `
  -Force `
  -AllowClobber
Import-Module Invoke-AtomicRedTeam -RequiredVersion $InvokeAtomicVersion -Force

$totalTargets = @($targetsDocument.atomics).Count
for ($index = 0; $index -lt $totalTargets; $index++) {
  $target = $targetsDocument.atomics[$index]
  $currentTarget = $index + 1
  $percentComplete = [math]::Round(($currentTarget / $totalTargets) * 100, 0)
  Write-Progress `
    -Activity "Verifying atomics for $($targetsDocument.platform)" `
    -Status "[$currentTarget/$totalTargets] $($target.atomic_id) - $($target.name)" `
    -PercentComplete $percentComplete
  Write-AtomicProgressLog `
    -Platform $targetsDocument.platform `
    -Target $target `
    -CurrentTarget $currentTarget `
    -TotalTargets $totalTargets `
    -PercentComplete $percentComplete

  $stages = [System.Collections.Generic.List[object]]::new()
  $status = "failed"
  $errorMessage = ""

  $prereqsOk = Add-Stage -Stages $stages -Name "check_prereqs" -ScriptBlock {
    Invoke-AtomicStage -Target $target -CheckPrereqs
  }
  if (-not $prereqsOk) {
    $prereqsOk = Add-Stage -Stages $stages -Name "get_prereqs" -ScriptBlock {
      Invoke-AtomicStage -Target $target -GetPrereqs
    }
    if ($prereqsOk) {
      $prereqsOk = Add-Stage -Stages $stages -Name "recheck_prereqs" -ScriptBlock {
        Invoke-AtomicStage -Target $target -CheckPrereqs
      }
    }
  }

  if ($prereqsOk) {
    $executed = Add-Stage -Stages $stages -Name "execute" -ScriptBlock {
      Invoke-AtomicStage -Target $target
    }
    if ($executed) {
      $status = "passed"
    }
  }

  $cleaned = Add-Stage -Stages $stages -Name "cleanup" -ScriptBlock {
    Invoke-AtomicStage -Target $target -Cleanup
  }
  if (-not $cleaned) {
    $status = "failed"
  }

  $failedStage = $stages | Where-Object { $_.status -eq "failed" } | Select-Object -First 1
  if ($failedStage) {
    $errorMessage = $failedStage.error
  }
  $exitCode = 0
  if ($failedStage) {
    $exitCode = $failedStage.exit_code
  }
  $stdout = (($stages | ForEach-Object { $_.stdout }) | Where-Object { $_ }) -join "`n"
  $stderr = (($stages | ForEach-Object { $_.stderr }) | Where-Object { $_ }) -join "`n"

  $results.Add([ordered]@{
      guid = $target.guid
      atomic_id = $target.atomic_id
      technique = $target.technique
      test_number = $target.test_number
      name = $target.name
      platform = $target.platform
      status = $status
      verified_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
      run_id = $runId
      error = $errorMessage
      exit_code = $exitCode
      stdout = $stdout
      stderr = $stderr
      stages = $stages
    })
}
Write-Progress -Activity "Verifying atomics for $($targetsDocument.platform)" -Completed

$output = [ordered]@{
  version = 1
  platform = $targetsDocument.platform
  results = $results
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
  New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}
$output | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding utf8

if ($results | Where-Object { $_.status -ne "passed" }) {
  exit 1
}
