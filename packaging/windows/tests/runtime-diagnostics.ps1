#requires -Version 5.1
#requires -RunAsAdministrator
<#
Verify controlled prerequisite failures and unwritable diagnostics without
installing the runtime. Downloads Microsoft's prerequisite, then rejects its
signature through a scoped test double before execution can occur.
#>
[CmdletBinding()]
param([switch]$AllowRuntimeDownload)
$ErrorActionPreference = 'Stop'
if (!$AllowRuntimeDownload) { throw 'Use -AllowRuntimeDownload to allow the prerequisite download test.' }
$root = Join-Path $env:TEMP ('packettale-runtime-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
try {
    & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect test files.' }
    $helper = Join-Path $PSScriptRoot '..\install-runtime.ps1'
    function Get-AuthenticodeSignature { param($FilePath); [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null} }
    $log = Join-Path $root 'runtime.log'
    foreach ($destination in @($log, $root)) {
        $failure = ''
        try { & $helper -LogPath $destination } catch { $failure = $_.Exception.Message }
        if (!$failure.Contains('The Microsoft runtime signature could not be verified.')) {
            throw ('Expected signature validation failure, received: ' + $failure)
        }
    }
    $diagnostics = [IO.File]::ReadAllText($log)
    if (!$diagnostics.Contains('Failed at Verify Microsoft runtime signature; status HashMismatch')) {
        throw 'The failing prerequisite stage and status were not retained.'
    }
    if ($diagnostics.Contains('Authorization:') -or $diagnostics.Contains('enrollment_token')) {
        throw 'Unexpected sensitive data in diagnostics.'
    }
    Write-Output 'Runtime diagnostic failure paths verified; no runtime installer was executed.'
} finally {
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}
