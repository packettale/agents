#requires -Version 5.1
#requires -RunAsAdministrator
# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$InstallDirectory)
$ErrorActionPreference = 'Stop'
$removalStarted = $false

# Keep a native process handle between checking its image and terminating it.
# A process name or a PID alone is not sufficient proof of ownership.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class PacketTaleRemoval {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);

    static bool IsOwned(SafeProcessHandle process, string root) {
        var path = new StringBuilder(32768);
        int size = path.Capacity;
        if (!QueryFullProcessImageName(process, 0, path, ref size)) return false;
        string image = path.ToString();
        if (image.StartsWith(@"\\?\")) image = image.Substring(4);
        image = Path.GetFullPath(image);
        return image.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            && !String.Equals(Path.GetFileName(image), "uninstall.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static int Sweep(string directory, bool terminate) {
        string root = Path.GetFullPath(directory).TrimEnd('\\') + @"\";
        int count = 0;
        foreach (var process in Process.GetProcesses()) {
            using (process) {
                // QUERY_LIMITED_INFORMATION | SYNCHRONIZE, plus TERMINATE only
                // after a separate query has established installation ownership.
                using (var query = OpenProcess(0x101000, false, process.Id)) {
                    if (query.IsInvalid || !IsOwned(query, root) || WaitForSingleObject(query, 0) == 0) continue;
                    count++;
                    if (!terminate) continue;
                    using (var target = OpenProcess(0x101001, false, process.Id)) {
                        if (target.IsInvalid) {
                            if (WaitForSingleObject(query, 0) == 0) continue;
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not terminate an installation process");
                        }
                        if (!IsOwned(target, root)) throw new InvalidOperationException("Process ownership changed");
                        if (!TerminateProcess(target, 1) && WaitForSingleObject(target, 0) != 0)
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not terminate an installation process");
                    }
                }
            }
        }
        return count;
    }
}
'@

function Get-ServiceImage([string]$Name) {
    $path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\' + $Name
    if (Test-Path -LiteralPath $path) {
        return [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath $path -Name ImagePath).ImagePath)
    }
    return $null
}

function Test-ServiceImage([string]$Image, [string]$Expected) {
    $imagePath = $Image.Trim()
    if ($imagePath.StartsWith('\??\')) { $imagePath = $imagePath.Substring(4) }
    if ($imagePath.StartsWith('"')) {
        $end = $imagePath.IndexOf('"', 1)
        return $end -gt 0 -and [string]::Equals($imagePath.Substring(1, $end - 1), $Expected, [StringComparison]::OrdinalIgnoreCase)
    }
    return [string]::Equals($imagePath, $Expected, [StringComparison]::OrdinalIgnoreCase) -or
        $imagePath.StartsWith($Expected + ' ', [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-ServiceControl([string[]]$Arguments) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $env:WINDIR 'System32\sc.exe'
    $info.Arguments = $Arguments -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        if (!$process.WaitForExit(5000)) {
            $process.Kill()
            return 124
        }
        return $process.ExitCode
    } finally { $process.Dispose() }
}

function Get-ServiceState([string]$Name) {
    $controller = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (!$controller) { return 'Absent' }
    try { return $controller.Status.ToString() } finally { $controller.Dispose() }
}

try {
    $directory = Get-Item -LiteralPath $InstallDirectory -Force
    if ($directory -isnot [IO.DirectoryInfo] -or !$directory.Parent) { throw 'Invalid installation directory.' }
    for ($ancestor = $directory; $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'The installation directory is redirected. No processes were stopped.'
        }
    }
    $InstallDirectory = $directory.FullName.TrimEnd('\')
    $core = Join-Path $InstallDirectory 'packettale-core.exe'
    $image = Get-ServiceImage 'packettale-core'
    if ($image) {
        if (!(Test-ServiceImage $image $core)) { throw 'The core service belongs to another installation. No processes were stopped.' }
        if ((Invoke-ServiceControl @('config', 'packettale-core', 'start=', 'disabled')) -ne 0) {
            throw 'Could not disable service startup. No processes were stopped.'
        }
        $removalStarted = $true
        # A pending or failed stop still proceeds to bounded process termination.
        $null = Invoke-ServiceControl @('stop', 'packettale-core')
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([PacketTaleRemoval]::Sweep($InstallDirectory, $false) -gt 0 -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $removalStarted = $true
    do {
        $null = [PacketTaleRemoval]::Sweep($InstallDirectory, $true)
        if ([PacketTaleRemoval]::Sweep($InstallDirectory, $false) -eq 0 -and
            (Get-ServiceState 'packettale-core') -in @('Stopped', 'Absent')) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ([PacketTaleRemoval]::Sweep($InstallDirectory, $false) -gt 0) {
        throw 'Windows has not released an installation process.'
    }
    if ((Get-ServiceState 'packettale-core') -notin @('Stopped', 'Absent')) {
        throw 'Windows has not released the core service.'
    }

    $driver = Get-ServiceImage 'PortmasterKext'
    if ($driver -and (Test-ServiceImage $driver (Join-Path $InstallDirectory 'packettale-kext.sys'))) {
        $null = Invoke-ServiceControl @('stop', 'PortmasterKext')
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ((Get-ServiceState 'PortmasterKext') -notin @('Stopped', 'Absent') -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if ((Get-ServiceState 'PortmasterKext') -notin @('Stopped', 'Absent')) {
            throw 'Windows has not unloaded the installation driver.'
        }
        if ((Get-ServiceState 'PortmasterKext') -ne 'Absent' -and (Invoke-ServiceControl @('delete', 'PortmasterKext')) -ne 0) {
            throw 'Could not remove the stopped installation driver registration.'
        }
    } elseif ($driver) {
        Write-Host 'The driver belongs to another installation and was left unchanged.'
    }
    Write-Host 'Installation processes stopped and owned driver cleanup completed.'
    exit 0
} catch {
    Write-Host ('Agent cleanup did not complete: ' + $_.Exception.Message)
    if ($removalStarted) {
        Write-Host 'Reboot Windows and run this uninstaller again. No automatic reboot was requested; the core service will not be restarted by removal.'
        exit 3010
    }
    exit 1
}
