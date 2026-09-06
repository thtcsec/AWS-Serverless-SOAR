# Build Lambda deployment zip: src/ + pip deps (for terraform lab)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Build = Join-Path $Root "terraform\.lambda_build"
$Zip = Join-Path $Root "terraform\lambda_package.zip"
$Req = Join-Path $Root "src\requirements.txt"

Write-Host "==> Build Lambda package"
if (Test-Path $Build) { Remove-Item $Build -Recurse -Force }
New-Item -ItemType Directory -Path $Build | Out-Null

Write-Host "pip install -> $Build"
$pipArgs = @(
    "install", "-r", $Req, "-t", $Build,
    "--platform", "manylinux2014_x86_64",
    "--implementation", "cp",
    "--python-version", "3.12",
    "--only-binary=:all:",
    "--upgrade"
)
python -m pip @pipArgs
if ($LASTEXITCODE -ne 0) {
    Write-Warn "manylinux wheels failed — fallback pip (lab only)"
    python -m pip install -r $Req -t $Build --upgrade
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
}

Copy-Item -Path (Join-Path $Root "src") -Destination (Join-Path $Build "src") -Recurse -Force
Get-ChildItem $Build -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $Build -Recurse -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue

if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path (Join-Path $Build "*") -DestinationPath $Zip -Force
Write-Host "[OK] $Zip ($([math]::Round((Get-Item $Zip).Length / 1MB, 2)) MB)"
