#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PurgeScript, [switch]$AllowPurge)
$ErrorActionPreference = 'Stop'
if (!$AllowPurge) { throw 'Use -AllowPurge only on a disposable Windows test VM.' }
if (!(Test-Path -LiteralPath $PurgeScript -PathType Leaf)) { throw 'The explicit purge helper is missing.' }
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'packettale'
if (Test-Path -LiteralPath $data) { throw 'The test requires an empty machine without existing endpoint data.' }
$outside = Join-Path ([IO.Path]::GetTempPath()) ('enterprise-purge-test-' + [Guid]::NewGuid())
$lock = $null
try {
    New-Item -ItemType Directory -Path $data, $outside | Out-Null
    $locked = Join-Path $data 'locked.db'
    [IO.File]::WriteAllText($locked, 'retain while locked')
    $lock = [IO.File]::Open($locked, 'Open', 'Read', 'None')
    $failed = $false
    try { & $PurgeScript -ConfirmPurge } catch { $failed = $true }
    if (!$failed -or !(Test-Path -LiteralPath $locked)) { throw 'A locked data file did not report failure and remain present.' }
    $lock.Dispose(); $lock = $null
    [IO.File]::WriteAllText((Join-Path $outside 'sentinel'), 'retain outside endpoint')
    New-Item -ItemType Junction -Path (Join-Path $data 'external') -Target $outside | Out-Null
    $readOnly = Join-Path $data 'read-only.txt'
    [IO.File]::WriteAllText($readOnly, 'remove endpoint data')
    [IO.File]::SetAttributes($readOnly, [IO.FileAttributes]::ReadOnly)
    & $PurgeScript -ConfirmPurge
    if (Test-Path -LiteralPath $data) { throw 'Endpoint data remained after explicit purge.' }
    if ([IO.File]::ReadAllText((Join-Path $outside 'sentinel')) -ne 'retain outside endpoint') { throw 'Purge followed an external directory junction.' }
    New-Item -ItemType Junction -Path $data -Target $outside | Out-Null
    $failed = $false
    try { & $PurgeScript -ConfirmPurge } catch { $failed = $true }
    if (!$failed -or !(Test-Path -LiteralPath (Join-Path $outside 'sentinel'))) { throw 'Purge did not refuse a redirected data root.' }
    [IO.Directory]::Delete($data)
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::Registry64)
    $keyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale'
    $existing = $registry.OpenSubKey($keyName)
    if ($existing) { $existing.Dispose(); $registry.Dispose(); throw 'The fresh-VM test found an existing uninstall registration.' }
    try {
        $install = Join-Path $outside 'installation'
        New-Item -ItemType Directory -Path $install | Out-Null
        Copy-Item -LiteralPath $PurgeScript -Destination (Join-Path $install 'purge-data.ps1')
        [IO.File]::WriteAllText((Join-Path $install 'uninstall.exe'), 'test registration only')
        [IO.File]::WriteAllText((Join-Path $install 'index.json'), '{"Name":"packettale Binaries"}')
        New-Item -ItemType Directory -Path (Join-Path $install 'upgrade_obsolete_binaries') | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $install 'upgrade_obsolete_binaries\external') -Target $outside | Out-Null
        $key = $registry.CreateSubKey($keyName)
        try { $key.SetValue('UninstallString', '"' + (Join-Path $install 'uninstall.exe') + '"') } finally { $key.Dispose() }
        & (Join-Path $install 'purge-data.ps1') -ConfirmPurge -RemoveReleaseCache
        if ((Test-Path -LiteralPath (Join-Path $install 'index.json')) -or
            (Test-Path -LiteralPath (Join-Path $install 'upgrade_obsolete_binaries')) -or
            !(Test-Path -LiteralPath (Join-Path $install 'uninstall.exe')) -or
            !(Test-Path -LiteralPath (Join-Path $outside 'sentinel'))) { throw 'Owned release-cache cleanup failed or removed unrelated files.' }
    } finally { $registry.DeleteSubKeyTree($keyName, $false); $registry.Dispose() }
    [pscustomobject]@{ LockedFileFailure = $true; ReadOnlyRemoved = $true; ExternalJunctionPreserved = $true; RedirectedRootRefused = $true; OwnedReleaseCacheRemoved = $true; UninstallFilesRetained = $true } | ConvertTo-Json
} finally {
    if ($lock) { $lock.Dispose() }
    if (Test-Path -LiteralPath $data) { throw 'Purge test left data; inspect this disposable VM before cleanup.' }
    if (Test-Path -LiteralPath $outside) { [IO.Directory]::Delete($outside, $true) }
}
