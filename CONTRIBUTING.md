# Contributing

Use the Go toolchain in [go.mod](go.mod). Run `go test -short ./...` and
`go vet ./...` before submitting Go changes. For Windows protocol changes, install
Rust and run `sh windows_kext/test_protocol.sh`.

The two cross-language protocol fixtures contain generated messages. To refresh
them after changing the wire format, run the producers, then run the protocol tests:

```sh
PACKETTALE_GENERATE_PROTOCOL_FIXTURES=1 go test -count=1 -run '^TestGenerateCommandFile$' ./windows_kext/kextinterface
PACKETTALE_GENERATE_PROTOCOL_FIXTURES=1 cargo test --locked --manifest-path windows_kext/protocol/Cargo.toml generate_test_info_file
sh windows_kext/test_protocol.sh
```

Run installer, service, firewall, and DNS integration tests on a disposable device
that matches the target operating system.

For a bug report, include your operating system, agent version, and steps to
reproduce the issue. Remove enrollment credentials, device names, addresses,
and connection history from any logs you share. Use the [security reporting
instructions](SECURITY.md) for vulnerabilities.
