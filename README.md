# PacketTale Agents

PacketTale agents enforce application firewall and DNS policies on managed Windows
and Linux devices. They run as background services and report network activity
to the PacketTale portal, where administrators publish policies, review summaries,
and investigate connections on online devices.

## Install an agent

In your PacketTale portal, open **Enrollment** and create an invitation. Use the
installation command or download the installer and enrollment configuration for
the target device. Run the installer with administrator privileges.

- [Windows installation](https://packettale.com/docs/install/windows/)
- [Debian and Ubuntu installation](https://packettale.com/docs/install/debian-ubuntu/)
- [Fedora installation](https://packettale.com/docs/install/fedora/)

An enrolled device keeps enforcing its last published policy when it loses contact
with the portal. Device traffic uses its normal network connection.

## Data and updates

Agents routinely send aggregate application, destination, and traffic summaries.
Detailed connection history stays on the device for 30 days by default. An authorised
administrator can query history from an online device and save selected results in
the portal. Routine telemetry excludes packet contents and decrypted HTTPS content.

The management channel uses mutually authenticated TLS 1.3 with hybrid
X25519MLKEM768 key agreement inside outbound HTTPS WebSockets. Agents verify signed
software updates approved in the portal. Safing intelligence updates use their own
signature verification.

## Build from source

Use the Go toolchain declared in [go.mod](go.mod). From the repository root, run:

```sh
go generate ./cmds/packettale-core
go build -trimpath -o dist/ ./cmds/packettale-core
go test -short ./...
```

The build produces the core executable for the current platform. For installer
payloads, the Windows DLL, and native packaging, see [Building installers](BUILDING.md).

## Contributing

See [Contributing](CONTRIBUTING.md) for tests and issue reports, and
[Security](SECURITY.md) for private vulnerability reporting.

## Licence and attribution

PacketTale agents are distributed under [GPLv3](LICENSE) and are derived from
[Safing Portmaster](https://github.com/safing/portmaster). PacketTale is independent
of Safing. Existing [attribution](AUTHORS), [trademark notices](TRADEMARKS), and
third-party licences are retained.
