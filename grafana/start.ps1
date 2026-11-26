# Start the local Grafana with the iot-project dashboard at http://localhost:3000.
# Uses your AWS profile only to assume the project's read-only Grafana role.
param(
    [string]$AwsProfile = $(if ($env:AWS_PROFILE) { $env:AWS_PROFILE } else { "default" })
)
$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
$grafanaHome = Join-Path $root "tools\grafana"
$exe = Join-Path $grafanaHome "bin\grafana.exe"
if (-not (Test-Path $exe)) {
    throw "Grafana is not installed. Run: powershell -File grafana\install.ps1"
}

# A shell opened before Terraform was installed has a stale PATH; reload it from the registry.
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
}
$outputs = terraform "-chdir=$root\infra" output -json | ConvertFrom-Json
if (-not $outputs.grafana_role_arn) {
    throw "Terraform outputs not found - deploy the stack first (make deploy)."
}

$env:AWS_PROFILE = $AwsProfile
$env:IOT_GRAFANA_ROLE_ARN = $outputs.grafana_role_arn.value
$env:IOT_REGION = $outputs.region.value
$env:IOT_DASHBOARDS_DIR = Join-Path $PSScriptRoot "dashboards"

$data = Join-Path $root "build\grafana"
$env:GF_PATHS_DATA = Join-Path $data "data"
$env:GF_PATHS_LOGS = Join-Path $data "logs"
$env:GF_PATHS_PLUGINS = Join-Path $data "plugins"
foreach ($dir in $env:GF_PATHS_DATA, $env:GF_PATHS_LOGS, $env:GF_PATHS_PLUGINS) {
    New-Item -ItemType Directory -Force $dir | Out-Null
}
$env:GF_PATHS_PROVISIONING = Join-Path $PSScriptRoot "provisioning"
$env:GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH = Join-Path $env:IOT_DASHBOARDS_DIR "iot-project.json"

Write-Host "Grafana: http://localhost:3000  (AWS profile '$AwsProfile' -> $($env:IOT_GRAFANA_ROLE_ARN))"
& $exe server --homepath $grafanaHome --config (Join-Path $PSScriptRoot "grafana.ini")
