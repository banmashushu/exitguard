#!/usr/bin/env python3
"""Verify a staged native arm64 bundle and its archive without launching it."""

import hashlib
import json
import pathlib
import plistlib
import struct
import subprocess
import sys
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    require(len(sys.argv) == 3, "usage: verify-macos-desktop.py APP_DIR ARCHIVE.zip")
    app, archive_path = map(pathlib.Path, sys.argv[1:])
    require(app.name == "ExitGuard.app" and app.is_dir() and not app.is_symlink(), "invalid staged application")
    contents = app / "Contents"
    plist = plistlib.loads((contents / "Info.plist").read_bytes())
    expected_version = json.loads((pathlib.Path(__file__).resolve().parents[1] / "mygo.json").read_text())["version"]
    require(plist.get("CFBundleShortVersionString") == expected_version and plist.get("CFBundleVersion") == expected_version, "wrong application version")
    require(plist.get("CFBundleIdentifier") == "com.exitguard.app", "wrong bundle identity")
    require(plist.get("CFBundleExecutable") == "ExitGuard", "wrong executable")
    require(plist.get("LSMinimumSystemVersion") == "13.0", "wrong macOS minimum")
    require(plist.get("CFBundleIconFile") == "AppIcon.icns", "missing configured icon")
    require({p.name for p in (contents / "MacOS").iterdir()} == {"ExitGuard"}, "legacy or unexpected helper executable")
    binary = contents / "MacOS" / "ExitGuard"
    magic, cpu, subtype, kind = struct.unpack_from("<IIII", binary.read_bytes())
    require(magic == 0xFEEDFACF and cpu == 0x0100000C and kind == 2, "not an arm64 Mach-O executable")
    files = {}
    for path in app.rglob("*"):
        require(not path.is_symlink(), f"unexpected bundle symlink: {path.name}")
        if path.is_file():
            relative = path.relative_to(app)
            require(path.suffix.lower() not in {".html", ".htm", ".js", ".swift", ".go", ".exe"}, f"unexpected payload file: {relative}")
            require(path.name not in {"config.json", "exitguard-core"} and not path.name.endswith((".credentials.json", ".profiles.json")), "private or legacy payload")
            files[f"ExitGuard.app/{relative.as_posix()}"] = path.read_bytes()
    for name in ("README-zh-CN.txt", "THIRD-PARTY-NOTICES.txt"):
        require((contents / "Resources" / name).is_file(), f"missing {name}")
    icon = (contents / "Resources" / "AppIcon.icns").read_bytes()
    require(icon[:4] == b"icns" and struct.unpack_from(">I", icon, 4)[0] == len(icon), "invalid ICNS header")
    offset, sizes = 8, []
    while offset < len(icon):
        kind, length = struct.unpack_from(">4sI", icon, offset)
        require(length >= 8 and offset + length <= len(icon), "invalid ICNS chunk")
        png = icon[offset + 8:offset + length]
        require(png[:8] == b"\x89PNG\r\n\x1a\n", "non-PNG ICNS chunk")
        width, height = struct.unpack_from(">II", png, 16)
        require(width == height, "nonsquare ICNS image")
        sizes.append(width)
        offset += length
    require(set(sizes) >= {32, 64, 128, 256, 512, 1024}, "incomplete icon sizes")
    libraries = subprocess.check_output(["otool", "-L", str(binary)], text=True)
    require("WebKit" not in libraries and "WebView" not in libraries, "unexpected static WebView dependency")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)], check=True)
    signature = subprocess.check_output(["codesign", "-dv", "--verbose=4", str(app)], stderr=subprocess.STDOUT, text=True)
    require("Signature=adhoc" in signature and "Identifier=com.exitguard.app" in signature, "wrong signing identity")
    with zipfile.ZipFile(archive_path) as archive:
        require(archive.testzip() is None, "archive CRC failure")
        archived_files = [item for item in archive.infolist() if not item.is_dir()]
        require(len(archived_files) == len(files), "unexpected archive entries")
        require({item.filename for item in archived_files} == set(files), "archive differs from staged bundle")
        for item in archived_files:
            require(archive.read(item) == files[item.filename], f"archive content mismatch: {item.filename}")
    print("Verified: arm64 native bundle, com.exitguard.app, macOS13, complete ICNS, ad-hoc signature.")
    print(f"Verified: application version {expected_version}.")
    print("Verified: sole desktop executable, no bundled web frontend/legacy core/private config; archive matches bundle.")
    print(f"Archive bytes: {archive_path.stat().st_size}; SHA-256: {hashlib.sha256(archive_path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, struct.error, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print(f"Mac desktop verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
