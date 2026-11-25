# Separate native Mihomo importer

This small executable is distributed under GNU GPLv3, separately from the MIT
ExitGuard application. It links the unmodified Mihomo v1.19.33 conversion package
from commit 3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8. It never imports the adapter,
configuration, provider, listener or hub packages and never starts a core.

The application sends one bounded JSON request on stdin and privately captures
stdout. Each URI receives exactly one native configuration or `invalid_uri`.
Unknown URI metadata follows the upstream converter. All native logging is
silenced, panics become fixed errors, and only automatically generated WS
User-Agent defaults are stabilized to an existing upstream value. User pins,
authentication and transport options are preserved. Capability checks remain in
ExitGuard; conversion alone does not establish connectivity or TLS validity.

The surrounding Mihomo directory supplies the exact pinned source and vendor
archives and their license. This archive supplies the complete wrapper source,
tests and builder. From the ExitGuard checkout, with those verified archives:

    python3 scripts/build-native-importer.py all .work/native-importer --update-manifest
    python3 scripts/build-native-importer.py darwin/arm64 .work/native-importer --test

For a standalone rebuild, extract mihomo-source.tar.gz, then extract the vendor
archive beside its go.mod. Copy main.go/main_test.go into
cmd/exitguard-native-importer/ inside that source tree. With Go 1.27.3:

    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -mod=vendor -trimpath -buildvcs=false -ldflags '-s -w' -o mihomo-importer ./cmd/exitguard-native-importer

For Windows use GOOS=windows GOARCH=amd64 and add -H=windowsgui to ldflags.
Mac packaging applies ad-hoc signing to the helper before recording its SHA-256.
The embedded/generated importer manifest records core source/vendor digests,
wrapper source digest and both platform binary digests. Only the helper disables
VCS stamping, because its exact corresponding source is identified explicitly;
ExitGuard's main application retains normal VCS provenance.
