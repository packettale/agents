#requires -Version 5.1
#requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([switch]$ConfirmPurge, [switch]$RemoveReleaseCache)
$ErrorActionPreference = 'Stop'
if (!$ConfirmPurge) { throw 'Explicit confirmation is required to delete local endpoint data.' }
$service = Get-Service -Name packettale-core -ErrorAction SilentlyContinue
if ($service) {
    try {
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw 'Stop or uninstall the endpoint service before deleting its data.'
        }
    } finally { $service.Dispose() }
}
$dataPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'packettale'
$root = Get-Item -LiteralPath $dataPath -Force -ErrorAction SilentlyContinue
if ($root -and ($root -isnot [IO.DirectoryInfo] -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
    throw 'The endpoint data directory is redirected or has an unexpected type. No data was deleted.'
}
function Remove-EndpointNode([IO.FileSystemInfo]$Node) {
    if ($Node.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        # Delete the link itself; never recurse into a junction or symbolic link.
        $Node.Delete()
    } elseif ($Node -is [IO.DirectoryInfo]) {
        foreach ($child in $Node.GetFileSystemInfos()) { Remove-EndpointNode $child }
        $Node.Delete()
    } else {
        if ($Node.Attributes -band [IO.FileAttributes]::ReadOnly) {
            [IO.File]::SetAttributes($Node.FullName, [IO.FileAttributes]::Normal)
        }
        $Node.Delete()
    }
}
$releaseFiles = @()
if ($RemoveReleaseCache) {
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $registration = $registry.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale')
        if (!$registration) { throw 'The owned uninstall registration is missing. No data was deleted.' }
        try { $registered = $registration.GetValue('UninstallString') } finally { $registration.Dispose() }
    } finally { $registry.Dispose() }
    $expected = '"' + (Join-Path $PSScriptRoot 'uninstall.exe') + '"'
    if (![string]::Equals($registered, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The uninstall registration belongs to another directory. No data was deleted.'
    }
    $index = Get-Item -LiteralPath (Join-Path $PSScriptRoot 'index.json') -Force -ErrorAction SilentlyContinue
    if ($index) {
        if (!($index.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            if ($index.Length -gt 262144 -or (Get-Content -LiteralPath $index.FullName -Raw | ConvertFrom-Json).Name -ne 'packettale Binaries') {
                throw 'The software index is not owned by this installation. No data was deleted.'
            }
        }
        $releaseFiles += $index
    }
    $obsolete = Get-Item -LiteralPath (Join-Path $PSScriptRoot 'upgrade_obsolete_binaries') -Force -ErrorAction SilentlyContinue
    if ($obsolete) { $releaseFiles += $obsolete }
}
foreach ($item in $releaseFiles) { Remove-EndpointNode $item }
if ($root) { Remove-EndpointNode $root }
