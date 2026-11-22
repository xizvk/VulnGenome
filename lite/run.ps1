param(
  [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
$LiteRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent $LiteRoot
$Python = Join-Path $LiteRoot '.venv\Scripts\python.exe'
$RuntimeRoot = if ($env:VULNGENOME_LITE_DATA_DIR) { $env:VULNGENOME_LITE_DATA_DIR } else { Join-Path $LiteRoot '.runtime' }
$PipTemp = Join-Path $RuntimeRoot 'pip-tmp'
New-Item -ItemType Directory -Path $PipTemp -Force | Out-Null
$env:TEMP = $PipTemp
$env:TMP = $PipTemp

if (-not (Test-Path -LiteralPath $Python)) {
  $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
  if (-not $PythonCommand) { throw 'Python 3.12 was not found. Install Python 3.12, then run this script again.' }
  & $PythonCommand.Source -m venv (Join-Path $LiteRoot '.venv')
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the local Lite virtual environment.' }
}
$PythonVersion = & $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($PythonVersion -ne '3.12') { throw "VulnGenome Lite requires Python 3.12; found $PythonVersion." }
if (-not $SkipInstall) {
  & $Python -m pip install --no-cache-dir -r (Join-Path $LiteRoot 'requirements.txt')
  if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; see pip output above.' }
}
$env:VULNGENOME_LITE_DATA_DIR = $RuntimeRoot
$env:PYTHONPATH = (Join-Path $RepoRoot 'src')
Push-Location (Join-Path $LiteRoot 'backend')
try {
  & $Python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
} finally {
  Pop-Location
}
