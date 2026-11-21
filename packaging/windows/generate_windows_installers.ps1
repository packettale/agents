param(
    [string]$Payload = "dist/payload",
    [string]$Output = "dist/packettale-windows-amd64.exe",
    [string]$Version = "1.0.0"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path "$PSScriptRoot/../..").Path
$payloadPath = (Resolve-Path $Payload).Path
$outputPath = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force ([IO.Path]::GetDirectoryName($outputPath)) | Out-Null
& makensis -NOCD "-DINPUT=$payloadPath" "-DOUTPUT=$outputPath" "-DVERSION=$Version" "$repo/packaging/windows/packettale.nsi"
if ($LASTEXITCODE -ne 0) { throw "NSIS build failed: $LASTEXITCODE" }
