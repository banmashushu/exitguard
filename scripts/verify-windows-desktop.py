#!/usr/bin/env python3
"""Inspect release PE metadata and the exact portable-package allowlist."""

import hashlib
import json
import pathlib
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib


def require(condition, message):
    if not condition:
        raise ValueError(message)


class PE:
    def __init__(self, data):
        self.data = data
        require(data[:2] == b"MZ", "missing DOS header")
        pe = self.unpack("<I", 0x3C)[0]
        require(data[pe:pe + 4] == b"PE\0\0", "missing PE signature")
        self.machine, sections = self.unpack("<HH", pe + 4)
        optional_size = self.unpack("<H", pe + 20)[0]
        optional = pe + 24
        self.magic = self.unpack("<H", optional)[0]
        require(self.magic in (0x10B, 0x20B), "unsupported PE optional header")
        self.subsystem = self.unpack("<H", optional + 68)[0]
        directory = optional + (112 if self.magic == 0x20B else 96)
        self.directories = [self.unpack("<II", directory + 8 * i) for i in range(16)]
        self.sections = []
        for i in range(sections):
            section = optional + optional_size + 40 * i
            size, rva, raw_size, offset = self.unpack("<IIII", section + 8)
            self.sections.append((rva, max(size, raw_size), offset))

    def unpack(self, fmt, offset):
        return struct.unpack_from(fmt, self.data, offset)

    def rva_offset(self, rva):
        for start, size, offset in self.sections:
            if start <= rva < start + size:
                return offset + rva - start
        raise ValueError(f"RVA outside sections: {rva:x}")

    def resources(self, resource_type):
        resource_rva, resource_size = self.directories[2]
        require(resource_rva and resource_size, "missing resource directory")
        base = self.rva_offset(resource_rva)

        def entries(relative):
            header = base + relative
            named, ids = self.unpack("<HH", header + 12)
            return [self.unpack("<II", header + 16 + 8 * i) for i in range(named + ids)]

        types = [target for name, target in entries(0) if name == resource_type]
        require(len(types) == 1 and types[0] & 0x80000000, f"missing resource type {resource_type}")
        result = {}
        for resource_id, language_dir in entries(types[0] & 0x7FFFFFFF):
            require(not resource_id & 0x80000000 and language_dir & 0x80000000, "invalid named resource")
            languages = entries(language_dir & 0x7FFFFFFF)
            require(len(languages) == 1, f"ambiguous resource language {resource_type}/{resource_id}")
            target = languages[0][1]
            require(not target & 0x80000000, "resource does not point to data")
            data_rva, size = self.unpack("<II", base + target)
            offset = self.rva_offset(data_rva)
            require(resource_id not in result and offset + size <= len(self.data), "invalid resource bounds or duplicate")
            result[resource_id] = self.data[offset:offset + size]
        return result

    def resource(self, resource_type):
        resources = self.resources(resource_type)
        require(len(resources) == 1, f"ambiguous resource type {resource_type}")
        return next(iter(resources.values()))

    def icon_images(self):
        icons = self.resources(3)
        groups = self.resources(14)
        require(len(groups) == 1, "ambiguous icon groups")
        group = next(iter(groups.values()))
        reserved, kind, count = struct.unpack_from("<HHH", group)
        require(reserved == 0 and kind == 1 and count > 0 and len(group) == 6 + 14 * count, "invalid icon group")
        images, referenced = {}, set()
        for index in range(count):
            width, height, colors, unused, planes, bits, size, ident = struct.unpack_from("<BBBBHHIH", group, 6 + 14 * index)
            width, height = width or 256, height or 256
            require(colors == 0 and unused == 0 and planes == 1 and bits == 32, "invalid icon group format")
            require(ident in icons and ident not in referenced, "invalid or repeated icon reference")
            image = icons[ident]
            require(size == len(image), "icon group byte count mismatch")
            require(png_dimensions(image) == (width, height), "icon group dimensions mismatch")
            require(width == height and width not in images, "duplicate or nonsquare icon frame")
            images[width] = image
            referenced.add(ident)
        require(referenced == set(icons), "unreferenced icon resource")
        require(set(images) == {16, 24, 32, 48, 64, 128, 256}, "missing standard icon sizes")
        return images

    def manifest(self):
        return self.resource(24).rstrip(b"\0")

    def fixed_version(self):
        data = self.resource(16)
        signature = struct.pack("<I", 0xFEEF04BD)
        require(data.count(signature) == 1, "missing or ambiguous fixed version info")
        offset = data.index(signature)
        values = struct.unpack_from("<6I", data, offset)
        file_ms, file_ls, product_ms, product_ls = values[2:6]
        return ((file_ms >> 16, file_ms & 0xFFFF, file_ls >> 16, file_ls & 0xFFFF),
                (product_ms >> 16, product_ms & 0xFFFF, product_ls >> 16, product_ls & 0xFFFF))

    def imports(self):
        rva, size = self.directories[1]
        if not rva:
            return []
        offset = self.rva_offset(rva)
        names = []
        while True:
            descriptor = self.unpack("<IIIII", offset)
            if not any(descriptor):
                return names
            start = self.rva_offset(descriptor[3])
            names.append(self.data[start:self.data.index(b"\0", start)].decode("ascii"))
            offset += 20


def check_manifest(pe, label, explicit_execution_level=True):
    root = ET.fromstring(pe.manifest())
    execution = root.findall(".//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel")
    require(len(execution) <= 1, f"{label}: ambiguous execution level")
    require(not explicit_execution_level or execution, f"{label}: missing execution level")
    if execution:
        require(execution[0].attrib.get("level") == "asInvoker", f"{label}: requests elevation")
        require(execution[0].attrib.get("uiAccess", "false") == "false", f"{label}: requests UI access")
    require(not root.findall(".//{http://schemas.microsoft.com/SMI/2005/WindowsSettings}autoElevate"), f"{label}: requests automatic elevation")
    return root


def png_dimensions(data):
    require(data[:8] == b"\x89PNG\r\n\x1a\n", "icon is not PNG")
    offset, dimensions, ended = 8, None, False
    while offset < len(data):
        require(offset + 12 <= len(data), "truncated PNG chunk")
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 8 + size
        require(end + 4 <= len(data), "PNG chunk outside image")
        crc = struct.unpack_from(">I", data, end)[0]
        require(zlib.crc32(data[offset + 4:end]) & 0xFFFFFFFF == crc, "invalid PNG CRC")
        if offset == 8:
            require(kind == b"IHDR" and size == 13, "missing PNG header")
            width, height, depth, color, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", data, offset + 8)
            require(depth == 8 and color == 6 and compression == 0 and filtering == 0 and interlace == 0, "icon is not RGBA8 PNG")
            dimensions = width, height
        if kind == b"IEND":
            require(size == 0 and end + 4 == len(data), "invalid PNG ending")
            ended = True
        offset = end + 4
    require(dimensions and ended, "incomplete PNG")
    return dimensions


def ico_images(data):
    reserved, kind, count = struct.unpack_from("<HHH", data)
    require(reserved == 0 and kind == 1 and count == 7, "invalid ICO header")
    images, ranges = {}, []
    for index in range(count):
        width, height, colors, unused, planes, bits, size, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * index)
        width, height = width or 256, height or 256
        require(colors == 0 and unused == 0 and planes == 1 and bits == 32, "invalid ICO image format")
        require(offset >= 6 + 16 * count and size > 0 and offset + size <= len(data), "invalid ICO bounds")
        require(all(offset + size <= start or offset >= end for start, end in ranges), "overlapping ICO images")
        image = data[offset:offset + size]
        require(png_dimensions(image) == (width, height), "ICO dimensions mismatch")
        require(width == height and width not in images, "duplicate or nonsquare ICO image")
        images[width] = image
        ranges.append((offset, offset + size))
    require(set(images) == {16, 24, 32, 48, 64, 128, 256}, "missing ICO sizes")
    return images


def encode_ico(images):
    directory, payload = bytearray(struct.pack("<HHH", 0, 1, len(images))), bytearray()
    for size, image in sorted(images.items()):
        directory.extend(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(image), 6 + 16 * len(images) + len(payload)))
        payload.extend(image)
    return bytes(directory + payload)


def main():
    require(len(sys.argv) in (3, 4), "usage: verify-windows-desktop.py PORTABLE.zip SETUP.exe [UNINSTALLER.exe]")
    archive_path, installer_path = map(pathlib.Path, sys.argv[1:3])
    expected_version = json.loads((pathlib.Path(__file__).resolve().parents[1] / "mygo.json").read_text())["version"]
    version_parts = tuple(int(part) for part in expected_version.split("."))
    require(len(version_parts) == 3 and all(0 <= part <= 65535 for part in version_parts), "unsupported configured version")
    expected_fixed_version = version_parts + (0,)
    expected = {"ExitGuard.exe", "ExitGuard.ico", "README-zh-CN.txt", "THIRD-PARTY-NOTICES.txt", "SHA256SUMS.txt"}
    with zipfile.ZipFile(archive_path) as archive:
        require(set(archive.namelist()) == expected and len(archive.infolist()) == len(expected), "portable files differ from allowlist")
        require(archive.testzip() is None, "archive CRC failure")
        files = {name: archive.read(name) for name in expected}
        for info in archive.infolist():
            require(not info.is_dir() and not info.flag_bits & 1, "unexpected directory or encrypted entry")
            require((info.external_attr >> 16) & 0o170000 == 0o100000, "non-regular archive entry")
    checked = set()
    for line in files["SHA256SUMS.txt"].decode("ascii").splitlines():
        digest, name = line.split("  ", 1)
        require(name in expected - {"SHA256SUMS.txt"} and name not in checked, "unexpected checksum filename")
        require(hashlib.sha256(files[name]).hexdigest() == digest, f"checksum mismatch: {name}")
        checked.add(name)
    require(checked == expected - {"SHA256SUMS.txt"}, "incomplete checksums")

    app = PE(files["ExitGuard.exe"])
    require(app.machine == 0x8664 and app.magic == 0x20B, "desktop is not PE32+ AMD64")
    require(app.subsystem == 2, "desktop is not GUI subsystem")
    require(app.directories[4] == (0, 0), "unexpected signature state: re-check signed release policy")
    # MyGo 0.7.3 emits no trustInfo. There is no elevation request; the app
    # runs under the caller's token. The NSIS installer explicitly says asInvoker.
    app_manifest = check_manifest(app, "desktop", explicit_execution_level=False)
    require(b"com.exitguard.app" in app.manifest(), "wrong application identity")
    identity = app_manifest.find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
    require(identity is not None and identity.attrib.get("version") == expected_version + ".0", "wrong application manifest version")
    require(app.fixed_version() == (expected_fixed_version, expected_fixed_version), "wrong application file/product version")
    require(any(node.attrib.get("Id") == "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" for node in app_manifest.iter()), "missing Windows 10 compatibility")
    require(b"PerMonitorV2" in app.manifest(), "missing DPI awareness")
    require(not any("webview" in name.lower() for name in app.imports()), "unexpected static WebView import")
    brand = ico_images((pathlib.Path(__file__).resolve().parents[1] / "assets/app-icon.ico").read_bytes())
    require(app.icon_images() == brand and ico_images(files["ExitGuard.ico"]) == brand, "application/ICO does not match brand icon")
    require(set(app.resources(14)) == {1}, "runtime LoadIcon resource 1 is missing")

    installer = PE(installer_path.read_bytes())
    require(installer.subsystem == 2, "installer is not GUI subsystem")
    require(installer.directories[4] == (0, 0), "unexpected installer signature state")
    check_manifest(installer, "installer")
    require(installer.fixed_version() == (expected_fixed_version, expected_fixed_version), "wrong installer file/product version")
    require(installer.icon_images() == brand, "installer does not match brand icon")
    if len(sys.argv) == 4:
        uninstaller = PE(pathlib.Path(sys.argv[3]).read_bytes())
        require(uninstaller.subsystem == 2 and uninstaller.directories[4] == (0, 0), "invalid unsigned GUI uninstaller")
        check_manifest(uninstaller, "uninstaller")
        require(uninstaller.icon_images() == brand, "uninstaller does not match brand icon")
        print("Verified: exported NSIS uninstaller has the same brand icon and non-elevating manifest.")
    else:
        print("Uninstaller static check omitted: provide its NSIS compile-time export as the third argument.")
    print("Verified: AMD64 GUI, non-elevating manifests, unsigned app/setup, no static WebView import.")
    print(f"Verified: application and installer version {expected_version}.")
    print("Verified: brand-matching RGBA icons at 16/24/32/48/64/128/256px in app, setup and portable ICO.")
    print("Verified: portable allowlist, regular files, CRC and SHA-256; no user-data/source paths.")
    print("Package files: " + ", ".join(sorted(expected)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, struct.error, ET.ParseError, zipfile.BadZipFile) as exc:
        print(f"Windows desktop verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
