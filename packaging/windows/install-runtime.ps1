param([string]$LogPath)
# Native integration requires the Microsoft Visual C++ v14 x64 runtime.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$stage = 'Create protected runtime workspace'
$status = 'not available'
function Write-RuntimeDiagnostic([string]$Message) {
    if ($LogPath) {
        try { [IO.File]::AppendAllText($LogPath, "Runtime: $Message`r`n", [Text.UTF8Encoding]::new($false)) }
        catch { # Diagnostic storage must not prevent prerequisite validation or installation.
        }
    }
}
$work = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    & icacls.exe $work /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect runtime installation files.' }
    $file = Join-Path $work 'vc_redist.x64.exe'
    # Native curl handles IPv4/IPv6 fallback on dual-stack endpoint networks.
    $systemDirectory = if ([Environment]::Is64BitProcess) { 'System32' } else { 'Sysnative' }
    $curl = Join-Path $env:SystemRoot ($systemDirectory + '\curl.exe')
    $stage = 'Download Microsoft runtime'
    Write-RuntimeDiagnostic $stage
    & $curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --retry 2 --retry-max-time 120 --output $file 'https://aka.ms/vc14/vc_redist.x64.exe'
    $status = $LASTEXITCODE
    if ($status -ne 0) { throw 'Microsoft runtime download failed.' }
    $stage = 'Verify Microsoft runtime signature'
    $signature = Get-AuthenticodeSignature $file
    $status = [string]$signature.Status
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation,') {
        throw 'The Microsoft runtime signature could not be verified.'
    }
    $stage = 'Install Microsoft runtime'
    Write-RuntimeDiagnostic $stage
    $process = Start-Process $file -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
    $status = $process.ExitCode
    if ($process.ExitCode -notin @(0, 1638, 3010)) {
        throw "Microsoft runtime installation failed ($($process.ExitCode))."
    }
    Write-RuntimeDiagnostic "Completed; exit code $status"
} catch {
    Write-RuntimeDiagnostic "Failed at $stage; status $status"
    throw
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
