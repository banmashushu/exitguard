#!/usr/bin/env python3
"""Fetch only the pinned official assets, verifying before extraction/staging."""
import gzip
import hashlib
import io
import json
import pathlib
import ssl
import sys
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "internal/managedproxy/manifest.json").read_text())
CACHE = ROOT / ".work/managed-core"

def checked(data, digest):
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("managed core checksum mismatch")
    return data

def fetch(url, digest, cache):
    if cache.is_file():
        return checked(cache.read_bytes(), digest)
    # No inherited proxy settings or hooks; only fixed official HTTPS URLs.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(url, timeout=60) as response:
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024:
        raise ValueError("managed core asset too large")
    checked(data, digest)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    return data

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in MANIFEST["assets"]:
        raise ValueError("usage: fetch-managed-core.py darwin/arm64|windows/amd64")
    platform = sys.argv[1]
    item = MANIFEST["assets"][platform]
    archive = fetch(f'{MANIFEST["repository"]}/releases/download/{MANIFEST["version"]}/{item["name"]}', item["archive_sha256"], CACHE / "downloads" / item["name"])
    if item["name"].endswith(".gz"):
        binary = gzip.decompress(archive)
    else:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            if zipped.namelist() != ["mihomo-windows-amd64-v1.exe"]:
                raise ValueError("unexpected official managed core archive")
            binary = zipped.read(zipped.namelist()[0])
    checked(binary, item["binary_sha256"])
    target = CACHE / platform.replace("/", "-")
    target.mkdir(parents=True, exist_ok=True)
    path = target / item["binary"]
    path.write_bytes(binary)
    path.chmod(0o755)
    fetch(MANIFEST["source_url"], MANIFEST["source_sha256"], CACHE / "mihomo-source.tar.gz")
    fetch(MANIFEST["vendor_url"], MANIFEST["vendor_sha256"], CACHE / "mihomo-vendor.tar.gz")
    print(f"Verified official {MANIFEST['version']} core and corresponding source: {target}")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"Managed core fetch failed: {exc}", file=sys.stderr)
        sys.exit(1)
