#!/usr/bin/env python3
"""Losslessly wrap a MyGo-built EXE's standard PNG icon resources as an ICO.

Reproduce: python3 scripts/extract-windows-icon.py MYGO_BUILT.exe assets/app-icon.ico
MyGo's configured assets/app-icon.png is the source; no image is redrawn or
resampled here. Every PNG frame is preserved byte-for-byte from the PE.
"""

import pathlib
import runpy
import sys


def main():
    if len(sys.argv) != 3:
        raise ValueError("usage: extract-windows-icon.py MYGO_BUILT.exe OUTPUT.ico")
    api = runpy.run_path(str(pathlib.Path(__file__).with_name("verify-windows-desktop.py")))
    pe = api["PE"](pathlib.Path(sys.argv[1]).read_bytes())
    images = pe.icon_images()
    output = api["encode_ico"](images)
    assert api["ico_images"](output) == images
    pathlib.Path(sys.argv[2]).write_bytes(output)
    print("Extracted byte-identical brand PNG frames to ICO: " + ", ".join(map(str, sorted(images))))


if __name__ == "__main__":
    main()
