#requires -Version 5.1
#requires -RunAsAdministrator
<#
Exercises the installed Windows uninstaller under a real file lock.
Run only on a disposable VM: Transient removes the installed application.
No enrollment or history is deleted by this test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallDirectory,
    [Parameter(Mandatory = $true)][string]$DataDirectory,
    [ValidateSet('Transient', 'Timeout', 'TransientPayload', 'TimeoutPayload')][string]$Scenario = 'Transient',
    [switch]$AllowUninstall
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if (!$AllowUninstall) { throw 'Use -AllowUninstall only on a disposable test VM.' }
$InstallDirectory = (Resolve-Path -LiteralPath $InstallDirectory).Path.TrimEnd('\')
$DataDirectory = (Resolve-Path -LiteralPath $DataDirectory).Path.TrimEnd('\')
$expectedDataDirectory = (Resolve-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'packettale')).Path.TrimEnd('\')
if (![string]::Equals($DataDirectory, $expectedDataDirectory, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'DataDirectory does not match the enrolled package data directory. No removal was started.'
}

$core = Join-Path $InstallDirectory 'packettale-core.exe'
$uninstaller = Join-Path $InstallDirectory 'uninstall.exe'
$state = Join-Path $DataDirectory 'management-state.json'
$config = Join-Path $DataDirectory 'management.json'
$history = Join-Path $DataDirectory 'databases\history.db'
foreach ($path in @($core, $uninstaller, $state, $config, $history)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing test prerequisite: $path" }
}
$service = Get-CimInstance Win32_Service -Filter "Name='packettale-core'"
if (!$service -or $service.State -ne 'Running' -or !$service.PathName.StartsWith(('"' + $core + '"'), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The installed core service does not belong to the supplied directory.'
}
function Get-OwnedUninstallEntries {
    $entries = @()
    foreach ($view in @('Registry32', 'Registry64')) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::$view)
        try {
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale')
            if ($key) {
                try {
                    if ($key.GetValue('DisplayName') -ne 'packettale' -or
                        $key.GetValue('UninstallString') -ine ('"' + $uninstaller + '"')) {
                        throw 'Unexpected uninstall registration; refusing to run.'
                    }
                    $entries += $view
                } finally { $key.Dispose() }
            }
        } finally { $base.Dispose() }
    }
    return $entries
}
function Get-CoreServiceState {
    $controller = Get-Service -Name packettale-core -ErrorAction SilentlyContinue
    if (!$controller) { return 'Absent' }
    try { return $controller.Status.ToString() } finally { $controller.Dispose() }
}
$beforeEntries = @(Get-OwnedUninstallEntries)
if ($beforeEntries.Count -ne 1) { throw 'Expected exactly one owned uninstall registration.' }
$beforeState = (Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash
$beforeConfig = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
$payloadScenario = $Scenario.EndsWith('Payload')
if ($payloadScenario -and !(Test-Path -LiteralPath (Join-Path $InstallDirectory 'purge-data.ps1'))) {
    throw 'Payload-lock checks require the current installer with its retained removal helper.'
}
$lockTarget = if ($payloadScenario) { Join-Path $InstallDirectory 'packettale-core.dll' } else { $core }
$lockSeconds = if ($Scenario.StartsWith('Transient')) { 3 } else { 60 }
# Permit execution/read/write; deny delete until the test releases its handle.
$lock = [IO.File]::Open($lockTarget, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
$job = $null
try {
    $job = Start-Job -ArgumentList $uninstaller, $core -ScriptBlock {
        param($uninstaller, $core)
        $ErrorActionPreference = 'Stop'
        $timer = [Diagnostics.Stopwatch]::StartNew()
        # NSIS normally detaches a temporary copy, hiding its real exit code.
        # Run an explicit copy outside the installation with _?= instead.
        $runner = Join-Path $env:TEMP ('packettale-remove-' + [Guid]::NewGuid().ToString('N') + '.exe')
        Copy-Item -LiteralPath $uninstaller -Destination $runner
        try {
            $process = Start-Process -FilePath $runner -ArgumentList ('/S _?=' + (Split-Path -Parent $uninstaller)) -Wait -PassThru
        } finally { Remove-Item -LiteralPath $runner -Force }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            ElapsedSeconds = $timer.Elapsed.TotalSeconds
            CorePresentWhenUninstallerFinished = Test-Path -LiteralPath $core
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $current = Get-CoreServiceState
        if ($current -eq 'Absent' -or $current -eq 'Stopped') { break }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Uninstaller did not stop the test core within 60 seconds.' }
        Start-Sleep -Milliseconds 100
    } while ($true)
    Wait-Job -Job $job -Timeout $lockSeconds | Out-Null
    $lock.Dispose()
    $lock = $null
    if (!(Wait-Job -Job $job -Timeout 90)) { throw 'Uninstaller did not finish within the bounded test interval.' }
    $result = Receive-Job -Job $job -ErrorAction Stop
    if (!$result -or $result.Count -gt 1) { throw 'Unexpected uninstaller test result.' }
    $entries = @(Get-OwnedUninstallEntries)
    $current = Get-CoreServiceState
    $preserved = ((Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash -eq $beforeState -and
        (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -eq $beforeConfig -and
        (Test-Path -LiteralPath $history -PathType Leaf))
    $report = [pscustomobject]@{
        Scenario = $Scenario
        ExitCode = $result.ExitCode
        ElapsedSeconds = [Math]::Round($result.ElapsedSeconds, 3)
        CorePresentWhenUninstallerFinished = $result.CorePresentWhenUninstallerFinished
        CorePresent = Test-Path -LiteralPath $core
        DLLPresent = Test-Path -LiteralPath (Join-Path $InstallDirectory 'packettale-core.dll')
        Service = $current
        UninstallerPresent = Test-Path -LiteralPath $uninstaller
        HelperPresent = Test-Path -LiteralPath (Join-Path $InstallDirectory 'purge-data.ps1')
        UninstallEntries = $entries
        EnrollmentConfigurationUnchanged = ((Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash -eq $beforeState -and (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -eq $beforeConfig)
        HistoryFilePresent = Test-Path -LiteralPath $history -PathType Leaf
    }
    $report | ConvertTo-Json -Depth 3
    if (!$preserved) { throw 'Removal altered enrollment/configuration or removed local history.' }
    if ($Scenario.StartsWith('Transient')) {
        if ($report.ExitCode -ne 0 -or $report.CorePresentWhenUninstallerFinished -or $report.CorePresent -or
            $report.DLLPresent -or $current -ne 'Absent' -or $entries.Count -ne 0) {
            throw 'Transient file lock prevented complete removal instead of being retried.'
        }
    } elseif ($payloadScenario) {
        if ($report.ExitCode -ne 3010 -or $report.CorePresent -or !$report.DLLPresent -or $report.Service -ne 'Absent' -or
            !$report.UninstallerPresent -or !$report.HelperPresent -or $entries.Count -ne 1 -or
            $report.ElapsedSeconds -lt 29 -or $report.ElapsedSeconds -gt 90) {
            throw 'Locked payload lost its reboot-required result or retained-data retry path.'
        }
    } else {
        if ($report.ExitCode -ne 3010 -or !$report.CorePresent -or !$report.DLLPresent -or $report.Service -ne 'Stopped' -or
            $entries.Count -ne 1 -or $report.ElapsedSeconds -lt 29 -or $report.ElapsedSeconds -gt 70) {
            throw 'Timed-out removal did not retain a stopped installation with a reboot-required result.'
        }
    }
} finally {
    if ($lock) { $lock.Dispose() }
    if ($job) {
        if ($job.State -eq 'Running') { Stop-Job -Job $job }
        Remove-Job -Job $job -Force
    }
}
