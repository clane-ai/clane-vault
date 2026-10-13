# Usage: .\update.ps1 [version]   e.g. .\update.ps1 0.2.0
param([string]$Version)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Test-Path .env)) { throw 'No .env here; run install.ps1 first.' }
if ($Version) {
  $lines = Get-Content .env
  if ($lines | Where-Object { $_ -like 'CLANE_VAULT_VERSION=*' }) {
    $lines = $lines | ForEach-Object { if ($_ -like 'CLANE_VAULT_VERSION=*') { "CLANE_VAULT_VERSION=$Version" } else { $_ } }
  } else { $lines += "CLANE_VAULT_VERSION=$Version" }
  [IO.File]::WriteAllLines((Join-Path $PWD '.env'), $lines)
}
docker compose pull
docker compose up -d
Write-Host ('Running version: ' + ((Get-Content .env | Where-Object { $_ -like 'CLANE_VAULT_VERSION=*' }) -replace 'CLANE_VAULT_VERSION=', ''))
