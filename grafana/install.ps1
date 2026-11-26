# Download portable Grafana OSS into tools/grafana (no admin rights, no Windows service).
# The archive is checked against Grafana's published SHA-256 before it is extracted.
param(
    [string]$Version = "13.2.4",
    [string]$Build = "38252365904"
)
$ErrorActionPreference = "Stop"

$root = Split-Path $PSScriptRoot -Parent
$target = Join-Path $root "tools\grafana"
if (Test-Path (Join-Path $target "bin\grafana.exe")) {
    Write-Host "Grafana already installed in $target"
    return
}

$url = "https://dl.grafana.com/grafana/release/$Version/grafana_${Version}_${Build}_windows_amd64.zip"
$download = Join-Path $root "tools\grafana-download"
New-Item -ItemType Directory -Force $download | Out-Null
$zip = Join-Path $download "grafana.zip"

Write-Host "Downloading $url (~470 MB)"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$expected = (Invoke-WebRequest -Uri "$url.sha256" -UseBasicParsing).Content.Trim().Split()[0]
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) {
    throw "Checksum mismatch: expected $expected, got $actual"
}

$extract = Join-Path $download "extract"
Expand-Archive -Path $zip -DestinationPath $extract -Force
New-Item -ItemType Directory -Force $target | Out-Null
Get-ChildItem (Get-ChildItem $extract -Directory | Select-Object -First 1).FullName | Move-Item -Destination $target
Remove-Item -Recurse -Force $download
Write-Host "Installed Grafana $Version in $target"
