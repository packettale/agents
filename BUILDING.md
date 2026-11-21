# Building PacketTale installers

The native installer recipes target x86-64 Windows, Debian/Ubuntu, and Fedora.
Use the Go toolchain in [go.mod](go.mod) and run commands from the repository root.

## Prepare the payload

Build the Windows core DLL with Visual Studio Build Tools and the Windows SDK:

```powershell
msbuild windows_core_dll/windows_core_dll.sln -t:Rebuild -p:Configuration=Release -p:Platform=x64
```

With [Earthly](https://earthly.dev/) installed, place the DLL at
`windows_core_dll/x64/Release/packettale-core.dll` and run:

```sh
earthly +release-prep
```

This target compiles the cores and verifies upstream indexes before downloading
the Safing intelligence files and the signed Windows kernel driver. It preserves
the signed driver bytes under the installer filename.

```text
dist/payload/
  intel/
  linux_amd64/
    packettale-core
  windows_amd64/
    packettale-core.exe
    packettale-core.dll
    packettale-kext.sys
```

## Build the packages

Install Bash, `dpkg-deb`, and `rpmbuild` for the Linux packages:

```sh
bash packaging/packettale/build-linux.sh dist/payload dist/packettale.deb 1.0.0
bash packaging/packettale/build-rpm.sh dist/payload dist/packettale.rpm 1.0.0
```

With NSIS installed, build the Windows package:

```powershell
powershell -NoProfile -File packaging/windows/generate_windows_installers.ps1 -Payload dist/payload -Version 1.0.0
```

The Windows installer includes the [SimpleSC service plugin](packaging/windows/service-plugin/),
with its source and licence in that directory. Windows Authenticode and PacketTale
release-manifest signing are separate from package assembly. Build artifacts require
the release signing and verification process before distribution.

For managed enrollment, obtain an invitation from the target PacketTale portal.
Keep its enrollment configuration outside the build tree and distribute it
only to the intended device.
