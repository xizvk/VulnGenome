$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BinaryDir = Join-Path $RepoRoot 'work\annotation-free-invariants-20261021\binaries'
$Vulnerable = Join-Path $BinaryDir 'transfer_vulnerable.so'
$Patched = Join-Path $BinaryDir 'transfer_patched.so'
foreach ($Path in @($Vulnerable, $Patched)) {
  if (-not (Test-Path -LiteralPath $Path)) { throw "Controlled demo binary is missing: $Path" }
}
$Raw = & curl.exe --silent --show-error --fail -F "vulnerable=@$Vulnerable" -F "patched=@$Patched" http://127.0.0.1:8000/api/v1/analyses
if ($LASTEXITCODE -ne 0) { throw 'Upload request failed. Start the local service first.' }
$Job = $Raw | ConvertFrom-Json
Write-Output "Created job: $($Job.id)"
Write-Output "Vulnerable SHA-256: $($Job.artifacts.vulnerable.sha256)"
Write-Output "Patched SHA-256:    $($Job.artifacts.patched.sha256)"
do {
  Start-Sleep -Seconds 1
  $Status = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/analyses/$($Job.id)"
  Write-Output "Stage: $($Status.stage)"
} while ($Status.status -eq 'running')
if ($Status.status -eq 'failed') { throw "Analysis failed: $($Status.error)" }
Write-Output "Analysis status: $($Status.result.analysis_status)"
if ($Status.result.verification) {
  Write-Output "Vulnerable: $($Status.result.verification.vulnerable.status) / $($Status.result.verification.vulnerable.solver_result)"
  Write-Output "Patched:    $($Status.result.verification.patched.status) / $($Status.result.verification.patched.solver_result)"
}
Write-Output "JSON report: http://127.0.0.1:8000/api/v1/analyses/$($Job.id)/report?format=json"
Write-Output "HTML report: http://127.0.0.1:8000/api/v1/analyses/$($Job.id)/report?format=html"
