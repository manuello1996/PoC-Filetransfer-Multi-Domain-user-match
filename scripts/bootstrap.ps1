param(
    [switch]$Reset
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $Root 'docker-compose.yml'

python (Join-Path $PSScriptRoot 'generate-domain-config.py')
if ($Reset) {
    Write-Warning 'Resetting all disposable PoC volumes, including identity links and uploaded files.'
    docker compose --project-directory $Root -f $ComposeFile down -v --remove-orphans
}
docker compose --project-directory $Root -f $ComposeFile up --build -d --remove-orphans
