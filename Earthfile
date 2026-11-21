VERSION 0.8

# Override custom_version to select the build and packaging version.
# Usage example: earthly --build-arg custom_version="1.2.3" +<target>
ARG --global custom_version = "1.0.0"

ARG --global go_version = 1.27.4
ARG --global rust_version = 1.89

ARG --global go_builder_image = "golang:${go_version}-alpine"
ARG --global rust_builder_image = "rust:${rust_version}-bookworm"
ARG --global work_image = "alpine"

ARG --global outputDir = "./dist"

# Architectures:
# The list of rust targets we support. They will be automatically converted
# to GOOS, GOARCH and GOARM when building go binaries. See the +RUST_TO_GO_ARCH_STRING
# helper method at the bottom of the file.
#
# Linux:
# x86_64-unknown-linux-gnu
# aarch64-unknown-linux-gnu
# armv7-unknown-linux-gnueabihf
# arm-unknown-linux-gnueabi
#
# Windows:
# x86_64-pc-windows-gnu
# aarch64-pc-windows-gnu
#
# Mac:
# x86_64-apple-darwin
# aarch64-apple-darwin

# Import the earthly rust lib since it already provides some useful
# build-targets and methods to initialize the rust toolchain.
IMPORT github.com/earthly/lib/rust:3.0.2 AS rust

go-ci:
    BUILD +go-build --GOOS="linux"   --GOARCH="amd64"
    BUILD +go-build --GOOS="linux"   --GOARCH="arm64"
    BUILD +go-build --GOOS="windows" --GOARCH="amd64"
    BUILD +go-build --GOOS="windows" --GOARCH="arm64"
    BUILD +go-test

kext-ci:
    BUILD +kext-build

release:
    LOCALLY

    IF ! git diff --quiet
        RUN echo -e "\033[1;31m Refusing to release a dirty git repository. Please commit your local changes first! \033[0m" ; exit 1
    END

    BUILD +go-ci

go-deps:
    FROM ${go_builder_image}
    WORKDIR /go-workdir

    # We need the git cli to extract version information for go-builds
    RUN apk add git

    # These cache dirs will be used in later test and build targets
    # to persist cached go packages.
    #
    # NOTE: cache only gets persisted on successful builds. A test
    # failure will prevent the go cache from being persisted.
    ENV GOCACHE = "/.go-cache"
    ENV GOMODCACHE = "/.go-mod-cache"

    # Copying only go.mod and go.sum means that the cache for this
    # target will only be busted when go.mod/go.sum change. This
    # means that we can cache the results of 'go mod download'.
    COPY go.mod .
    COPY go.sum .
    RUN go mod download

    # Explicitly cache here.
    SAVE IMAGE --cache-hint

go-base:
    FROM +go-deps

    COPY . .

    RUN GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go generate ./cmds/packettale-core

    # Explicitly cache here.
    SAVE IMAGE --cache-hint

# updates all go dependencies and runs go mod tidy, saving go.mod and go.sum locally.
go-update-deps:
    FROM +go-base

    RUN go get -u ./..
    RUN go mod tidy
    SAVE ARTIFACT --keep-ts go.mod AS LOCAL go.mod
    SAVE ARTIFACT --keep-ts --if-exists go.sum AS LOCAL go.sum

# mod-tidy runs 'go mod tidy', saving go.mod and go.sum locally.
mod-tidy:
    FROM +go-base

    RUN go mod tidy
    SAVE ARTIFACT --keep-ts go.mod AS LOCAL go.mod
    SAVE ARTIFACT --keep-ts --if-exists go.sum AS LOCAL go.sum

# go-build runs 'go build ./cmds/...', saving artifacts locally.
# If --CMDS is not set, it builds the PacketTale core.
go-build:
    FROM +go-base

    # Arguments for cross-compilation.
    ARG GOOS=linux
    ARG GOARCH=amd64
    ARG GOARM
    ARG CMDS=packettale-core

    CACHE --sharing shared "$GOCACHE"
    CACHE --sharing shared "$GOMODCACHE"

    RUN mkdir /tmp/build

    # Fall back to build all binaries when none is specified.
    IF [ "${CMDS}" = "" ]
        LET CMDS=$(ls -1 "./cmds/")
    END

    # Build all go binaries from the specified in CMDS
    FOR bin IN $CMDS
        RUN --no-cache CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-X github.com/packettale/agents/base/info.version=${custom_version}" -o "/tmp/build/" ./cmds/${bin}
    END

    DO +GO_ARCH_STRING --goos="${GOOS}" --goarch="${GOARCH}" --goarm="${GOARM}"
    FOR bin IN $(ls -1 "/tmp/build/")
        SAVE ARTIFACT --keep-ts "/tmp/build/${bin}" AS LOCAL "${outputDir}/${GO_ARCH_STRING}/${bin}"
    END

    SAVE ARTIFACT --keep-ts "/tmp/build/" ./output

# Test one or more go packages.
# Test are always run as -short, as "long" tests require a full desktop system.
# Run `earthly +go-test` to test all packages
# Run `earthly +go-test --PKG="service/firewall"` to only test a specific package.
# Run `earthly +go-test --TESTFLAGS="-args arg1"` to add custom flags to go test (-args in this case)
go-test:
    FROM +go-base

    ARG GOOS=linux
    ARG GOARCH=amd64
    ARG GOARM
    ARG TESTFLAGS
    ARG PKG="..."

    CACHE --sharing shared "$GOCACHE"
    CACHE --sharing shared "$GOMODCACHE"

    FOR pkg IN $(go list -e "./${PKG}")
        RUN --no-cache go test -cover -short ${pkg} ${TESTFLAGS}
    END

go-test-all:
    FROM ${work_image}
    ARG --required architectures

    FOR arch IN ${architectures}
        DO +RUST_TO_GO_ARCH_STRING --rustTarget="${arch}"
        BUILD +go-test --GOARCH="${GOARCH}" --GOOS="${GOOS}" --GOARM="${GOARM}"
    END

# Builds the PacketTale core for the requested platforms.
go-release:
    FROM ${work_image}
    ARG --required architectures

    FOR arch IN ${architectures}
        DO +RUST_TO_GO_ARCH_STRING --rustTarget="${arch}"

        IF [ -z GOARCH ]
            RUN echo "Failed to extract GOARCH for ${arch}"; exit 1
        END

        IF [ -z GOOS ]
            RUN echo "Failed to extract GOOS for ${arch}"; exit 1
        END

        BUILD +go-build --GOARCH="${GOARCH}" --GOOS="${GOOS}" --GOARM="${GOARM}"
    END

# Builds all binaries from the cmds/ folder for linux/windows AMD64
# Most utility binaries are never needed on other platforms.
go-build-utils:
    BUILD +go-build --CMDS="" --GOARCH=amd64 --GOOS=linux
    BUILD +go-build --CMDS="" --GOARCH=amd64 --GOOS=windows

# Assemble the installer payload from the core and verified upstream artifacts.
release-prep:
    FROM +go-base

    WORKDIR /app

    # Linux specific
    COPY (+go-build/output/packettale-core --GOARCH=amd64 --GOOS=linux --CMDS=packettale-core) ./output/binary/linux_amd64/packettale-core

    # Windows specific
    COPY (+go-build/output/packettale-core.exe --GOARCH=amd64 --GOOS=windows --CMDS=packettale-core) ./output/binary/windows_amd64/packettale-core.exe

    # All platforms

    # Build update manager
    COPY (+go-build/output/updatemgr --GOARCH=amd64 --GOOS=linux --CMDS=updatemgr) ./updatemgr
    # Obtain the unchanged upstream-signed kernel driver.
    RUN mkdir -p ./output/downloaded/windows_amd64 && ./updatemgr download https://updates.safing.io/stable.v3.json --trust binary --platform windows_amd64 ./output/downloaded/windows_amd64
    # Keep vendor-signed bytes intact while naming the distributed dependencies for packettale.
    RUN mv ./output/downloaded/windows_amd64/portmaster-kext.sys ./output/binary/windows_amd64/packettale-kext.sys
    RUN find ./output/downloaded/windows_amd64 -type f ! -name "packettale-kext.sys" -delete
    # Built from this repository by the Windows DLL workflow before release preparation.
    COPY ./windows_core_dll/x64/Release/packettale-core.dll ./output/binary/windows_amd64/packettale-core.dll
    # Get intel artifacts
    RUN mkdir -p ./output/intel && ./updatemgr download https://updates.safing.io/intel.v3.json --trust intel ./output/intel
    
    # Save all artifacts to output folder (on host)
    SAVE ARTIFACT --keep-ts "output/binary/linux_amd64/*"   AS LOCAL "${outputDir}/payload/linux_amd64/"
    SAVE ARTIFACT --keep-ts "output/binary/windows_amd64/*" AS LOCAL "${outputDir}/payload/windows_amd64/"
    SAVE ARTIFACT --keep-ts "output/intel/*"                AS LOCAL "${outputDir}/payload/intel/"

    # Save all artifacts to the container output folder so other containers can access it.
    SAVE ARTIFACT --keep-ts "output/binary/linux_amd64/*"   "output/binary/linux_amd64/"
    SAVE ARTIFACT --keep-ts "output/binary/windows_amd64/*" "output/binary/windows_amd64/"
    SAVE ARTIFACT --keep-ts "output/intel/*"                "output/intel/"

kext-build:
    FROM ${rust_builder_image}

    # Install architecture target
    DO rust+INIT --keep_fingerprints=true

    # Build kext
    WORKDIR /app/kext
    # --keep-ts is necessary to ensure that the timestamps of the source files
    # are preserved such that Rust's incremental compilation works correctly.
    COPY --keep-ts ./windows_kext/ .

    # Add target architecture
    RUN rustup target add x86_64-pc-windows-msvc
    
    # Build using special earthly lib
    WORKDIR /app/kext/release
    DO rust+CARGO --args="run"

    SAVE ARTIFACT --keep-ts "packettale-kext-release-bundle-*.zip" AS LOCAL "${outputDir}/windows_amd64/"


# Takes GOOS, GOARCH and optionally GOARM and creates a string representation for file-names.
# in the form of ${GOOS}_{GOARCH} if GOARM is empty, otherwise ${GOOS}_${GOARCH}v${GOARM}.
# Thats the same format as expected and served by our update server.
#
# The result is available as GO_ARCH_STRING environment variable in the build context.
GO_ARCH_STRING:
    FUNCTION
    ARG --required goos
    ARG --required goarch
    ARG goarm

    LET result = "${goos}_${goarch}"
    IF [ "${goarm}" != "" ]
        SET result = "${goos}_${goarch}v${goarm}"
    END

    ENV GO_ARCH_STRING="${result}"

# Takes a rust target (--rustTarget) and extracts architecture and OS and arm version
# and finally calls GO_ARCH_STRING.
#
# The result is available as GO_ARCH_STRING environment variable in the build context.
# It also exports GOOS, GOARCH and GOARM environment variables.
RUST_TO_GO_ARCH_STRING:
    FUNCTION
    ARG --required rustTarget

    LET goos=""
    IF [ -z "${rustTarget##*linux*}" ]
        SET goos="linux"
    ELSE IF [ -z "${rustTarget##*windows*}" ]
        SET goos="windows"
    ELSE IF [ -z "${rustTarget##*darwin*}" ]
        SET goos="darwin"
    ELSE
        RUN echo "GOOS not detected"; \
            exit 1;
    END

    LET goarch=""
    LET goarm=""
    IF [ -z "${rustTarget##*x86_64*}" ]
        SET goarch="amd64"
    ELSE IF [ -z "${rustTarget##*arm*}" ]
        SET goarch="arm"
        SET goarm="6"

        IF [ -z "${rustTarget##*v7*}" ]
            SET goarm="7"
        END
    ELSE IF [ -z "${rustTarget##*aarch64*}" ]
        SET goarch="arm64"
    ELSE
        RUN echo "GOARCH not detected"; \
            exit 1;
    END

    ENV GOOS="${goos}"
    ENV GOARCH="${goarch}"
    ENV GOARM="${goarm}"

    DO +GO_ARCH_STRING --goos="${goos}" --goarch="${goarch}" --goarm="${goarm}"

build:
    BUILD +go-build --GOOS=linux --GOARCH=amd64
    BUILD +go-build --GOOS=windows --GOARCH=amd64

installer-linux:
    FROM debian:trixie-slim
    RUN apt-get update && apt-get install -y --no-install-recommends bash coreutils dpkg rpm
    WORKDIR /app
    COPY packaging ./packaging
    COPY LICENSE ./LICENSE
    COPY (+release-prep/output/binary/linux_amd64) ./payload/linux_amd64
    COPY (+release-prep/output/intel) ./payload/intel
    RUN bash packaging/packettale/build-linux.sh /app/payload /app/packettale.deb "${custom_version}"
    RUN bash packaging/packettale/build-rpm.sh /app/payload /app/packettale.rpm "${custom_version}"
    SAVE ARTIFACT packettale.deb AS LOCAL "${outputDir}/linux_amd64/packettale.deb"
    SAVE ARTIFACT packettale.rpm AS LOCAL "${outputDir}/linux_amd64/packettale.rpm"

all-artifacts:
    BUILD +release-prep
    BUILD +installer-linux
