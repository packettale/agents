#requires -Version 5.1
#requires -RunAsAdministrator
<#
Native process/service removal qualification. Run on a Windows qualification VM
without an installed packettale-core service. Existing Portmaster is left alone.
#>
[CmdletBinding()]
param([switch]$AllowServiceTest)
$ErrorActionPreference = 'Stop'
if (!$AllowServiceTest) { throw 'Use -AllowServiceTest on a qualification VM.' }
if (Get-Service -Name packettale-core -ErrorAction SilentlyContinue) { throw 'An installed packettale service exists; no test was started.' }
$helper = (Resolve-Path (Join-Path $PSScriptRoot '..\stop-agent.ps1')).Path
$root = Join-Path $env:TEMP ('packettale-removal-' + [Guid]::NewGuid().ToString('N'))
$owned = Join-Path $root 'agent'
$foreign = $owned + '-other'
New-Item -ItemType Directory $owned, $foreign | Out-Null
$core = Join-Path $owned 'packettale-core.exe'
$otherCore = Join-Path $foreign 'packettale-core.exe'
$source = @'
using System;
using System.ServiceProcess;
using System.Threading;
class RemovalFixture : ServiceBase {
    static bool hang;
    public RemovalFixture() { ServiceName = "packettale-core"; }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { if (hang) Thread.Sleep(60000); }
    static void Main(string[] args) {
        if (Array.IndexOf(args, "--worker") >= 0) { Thread.Sleep(Timeout.Infinite); return; }
        hang = Array.IndexOf(args, "--unresponsive") >= 0;
        ServiceBase.Run(new RemovalFixture());
    }
}
'@
Add-Type -TypeDefinition $source -ReferencedAssemblies System.dll, System.ServiceProcess.dll -OutputAssembly $core -OutputType ConsoleApplication
Copy-Item -LiteralPath $core -Destination $otherCore
Copy-Item -LiteralPath $core -Destination (Join-Path $owned 'agent-worker.exe')
$driverPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortmasterKext'
$driverBefore = if (Test-Path $driverPath) { (Get-ItemProperty $driverPath).ImagePath } else { $null }
$driverState = (Get-Service PortmasterKext -ErrorAction SilentlyContinue).Status
$foreignProcess = $null
$createdService = $false
function Remove-FixtureService {
    $controller = Get-Service packettale-core -ErrorAction SilentlyContinue
    if ($controller) { $controller.Dispose(); & sc.exe delete packettale-core | Out-Null }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (Get-Service packettale-core -ErrorAction SilentlyContinue) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Fixture service deletion timed out.' }
        Start-Sleep -Milliseconds 200
    }
}
try {
    $foreignProcess = Start-Process -FilePath $otherCore -ArgumentList '--worker' -PassThru
    foreach ($scenario in @('graceful', 'duplicates', 'unresponsive', 'foreign-service')) {
        $image = if ($scenario -eq 'foreign-service') { $otherCore } else { $core }
        $arguments = if ($scenario -eq 'unresponsive') { ' --unresponsive' } else { '' }
        $service = New-Service -Name packettale-core -BinaryPathName ('"' + $image + '"' + $arguments) -StartupType Manual
        $service.Dispose()
        $createdService = $true
        Start-Service packettale-core
        if ($scenario -eq 'duplicates') {
            Start-Process -FilePath $core -ArgumentList '--worker' | Out-Null
            Start-Process -FilePath (Join-Path $owned 'agent-worker.exe') -ArgumentList '--worker' | Out-Null
        }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $helper + '"'),
            '-InstallDirectory', ('"' + $owned + '"')) -Wait -PassThru
        $foreignProcess.Refresh()
        if ($foreignProcess.HasExited) { throw 'An unrelated process was terminated.' }
        $state = Get-CimInstance Win32_Service -Filter "Name='packettale-core'"
        if ($scenario -eq 'foreign-service') {
            if ($process.ExitCode -eq 0 -or $state.State -ne 'Running') { throw 'Foreign service ownership was not enforced.' }
            Stop-Service packettale-core
        } else {
            if ($process.ExitCode -ne 0 -or $state.State -ne 'Stopped' -or $state.StartMode -ne 'Disabled') {
                throw ('Removal failed for ' + $scenario + '; exit ' + $process.ExitCode)
            }
            $remaining = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($owned + '\', [StringComparison]::OrdinalIgnoreCase) })
            if ($remaining.Count) { throw 'Owned installation processes survived cleanup.' }
            if ($timer.Elapsed.TotalSeconds -gt 50) { throw 'Process cleanup exceeded its time budget.' }
        }
        Remove-FixtureService
        $createdService = $false
        Write-Output ($scenario + ': PASS (' + [Math]::Round($timer.Elapsed.TotalSeconds, 1) + 's)')
    }
    $driverAfter = if (Test-Path $driverPath) { (Get-ItemProperty $driverPath).ImagePath } else { $null }
    if ($driverAfter -ne $driverBefore -or (Get-Service PortmasterKext -ErrorAction SilentlyContinue).Status -ne $driverState) {
        throw 'Another installation driver was changed.'
    }
    Write-Output 'Separate driver registration/state unchanged: PASS'
} finally {
    foreach ($process in @(Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and ($_.ExecutablePath.StartsWith($owned + '\', [StringComparison]::OrdinalIgnoreCase) -or $_.ExecutablePath -eq $otherCore)
    })) { Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue }
    if ($createdService) { Remove-FixtureService }
    if ($foreignProcess) { $foreignProcess.Dispose() }
    Remove-Item -LiteralPath $root -Recurse -Force
}
