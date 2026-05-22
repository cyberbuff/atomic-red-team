param(
  [Parameter(Mandatory = $true)]
  [string]$TargetsPath,

  [Parameter(Mandatory = $true)]
  [string]$OutputPath,

  [string]$AtomicsPath = (Join-Path (Get-Location) "atomics"),

  [string]$InvokeAtomicVersion = "2.3.0"
)

$ErrorActionPreference = "Stop"

function Add-Stage {
  param(
    [Parameter(Mandatory = $true)]
    [System.Collections.Generic.List[object]]$Stages,

    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [scriptblock]$ScriptBlock
  )

  $started = Get-Date
  try {
    & $ScriptBlock *> $null
    $Stages.Add([ordered]@{
        name = $Name
        status = "passed"
        duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
      })
    return $true
  }
  catch {
    $Stages.Add([ordered]@{
        name = $Name
        status = "failed"
        duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        error = $_.Exception.Message
      })
    return $false
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

foreach ($target in $targetsDocument.atomics) {
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
      stages = $stages
    })
}

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
