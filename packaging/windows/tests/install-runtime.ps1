#requires -Version 5.1
#requires -RunAsAdministrator
<#
Run only on a disposable x64 Windows VM with internet access.
Installs the actual Microsoft prerequisite using the installer's native host.
#>
[CmdletBinding()]
param([switch]$AllowRuntimeInstall)
$ErrorActionPreference = 'Stop'
if (!$AllowRuntimeInstall) { throw 'Use -AllowRuntimeInstall only on a disposable test VM.' }
if (![Environment]::Is64BitProcess) { throw 'Run this test in 64-bit PowerShell.' }
$runtime = Join-Path $env:SystemRoot 'System32\VCRUNTIME140.dll'
$helper = Join-Path $PSScriptRoot '..\install-runtime.ps1'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $helper
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $runtime)) {
    throw 'The runtime prerequisite did not install successfully.'
}
Write-Output 'Microsoft runtime prerequisite installed through the native installer host.'
