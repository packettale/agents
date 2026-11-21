#!/bin/sh
set -eu

cd "$(dirname "$0")"
cargo test --locked --manifest-path protocol/Cargo.toml
go test ./kextinterface
