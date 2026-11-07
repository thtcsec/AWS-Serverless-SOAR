$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot "..\..\.venv\Scripts\python.exe"
if (!(Test-Path -LiteralPath $python)) {
    $python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
}
& $python (Join-Path $PSScriptRoot "run_checks.py") @args
exit $LASTEXITCODE
