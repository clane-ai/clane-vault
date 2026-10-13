# Clane Vault installer (Windows). Safe to re-run: never overwrites an existing .env.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
# The image is public on ghcr.io. A private registry (set CLANE_VAULT_IMAGE in .env) needs REGISTRY, REGISTRY_USERNAME and REGISTRY_TOKEN.
$Registry = if ($env:REGISTRY) { $env:REGISTRY } else { 'ghcr.io' }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker is required.' }
docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose v2 is required.' }

$user = $env:REGISTRY_USERNAME
if ($user) {
  $token = $env:REGISTRY_TOKEN
  if (-not $token) { $s = Read-Host 'Registry token' -AsSecureString; $token = [Net.NetworkCredential]::new('', $s).Password }
  $token | docker login $Registry -u $user --password-stdin
  if ($LASTEXITCODE -ne 0) { throw 'docker login failed' }
}

function New-Hex([int]$bytes) { $b = New-Object byte[] $bytes; [Security.Cryptography.RandomNumberGenerator]::Fill($b); -join ($b | ForEach-Object { $_.ToString('x2') }) }
function Set-EnvVar($lines, $key, $value) { $lines | ForEach-Object { if ($_ -like "$key=*") { "$key=$value" } else { $_ } } }

if (-not (Test-Path .env)) {
  $bundled = Read-Host 'Use bundled Postgres? (y/n)'
  $url = Read-Host 'Public URL users will open (https://vault.example.com)'
  if (-not $url) { $url = 'https://vault.example.com' }
  $pg = New-Hex 24
  $lines = Get-Content .env.example
  $lines = Set-EnvVar $lines 'JWT_SECRET' (New-Hex 48)
  $lines = Set-EnvVar $lines 'SERVER_SECRET' (New-Hex 48)
  $lines = Set-EnvVar $lines 'POSTGRES_PASSWORD' $pg
  $lines = Set-EnvVar $lines 'PUBLIC_URL' $url
  if ($bundled -match '^[Yy]') {
    $lines = Set-EnvVar $lines 'DATABASE_URL' "postgresql://vault:$pg@postgres:5432/vault"
    $lines += 'COMPOSE_PROFILES=bundled-db'
  } else {
    $lines = Set-EnvVar $lines 'DATABASE_URL' (Read-Host 'DATABASE_URL of your Postgres')
  }
  [IO.File]::WriteAllLines((Join-Path $PWD '.env'), $lines)
  Write-Host 'Created .env'
} else { Write-Host '.env exists; keeping it.' }

# COMPOSE_PROFILES in .env enables the bundled database for every later compose command too.
docker compose pull
docker compose up -d

$port = ((Get-Content .env | Where-Object { $_ -like 'HTTP_PORT=*' }) -replace 'HTTP_PORT=', '') | Select-Object -First 1
if (-not $port) { $port = '8080' }
# Under a path (PUBLIC_URL=https://host/vault, or BASE_PATH) the API is at <path>/api/v1.
$base = ((Get-Content .env | Where-Object { $_ -like 'BASE_PATH=*' }) -replace '^BASE_PATH=', '') | Select-Object -First 1
if (-not $base) { $base = ((Get-Content .env | Where-Object { $_ -like 'PUBLIC_URL=*' }) -replace '^PUBLIC_URL=', '' -replace '^[A-Za-z]+://[^/]*', '') | Select-Object -First 1 }
if ($null -eq $base) { $base = '' }; $base = $base.Trim('/'); if ($base) { $base = "/$base" }
Write-Host 'Waiting for the server...'
$ok = $false
for ($i = 0; $i -lt 60 -and -not $ok; $i++) {
  try { Invoke-RestMethod "http://127.0.0.1:$port$base/api/v1/health" | Out-Null; $ok = $true } catch { Start-Sleep 2 }
}
if (-not $ok) { throw 'Server did not become healthy. Check: docker compose logs clane-vault' }
Write-Host "Clane Vault is running on 127.0.0.1:$port. Put an HTTPS reverse proxy in front of it."
Write-Host ''
Write-Host 'Create the first admin with:'
Write-Host '  docker compose exec clane-vault node dist/src/scripts/bootstrap.js --email <admin@yourcompany.com>'
