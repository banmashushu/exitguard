#!/usr/bin/env python3
"""Copy NSIS's compile-time uninstaller for static inspection; never run it."""

import pathlib
import shutil
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: capture-nsis-uninstaller.py NSIS_TEMP_FILE OUTPUT.exe")
source, output = map(pathlib.Path, sys.argv[1:])
if source.read_bytes()[:2] != b"MZ":
    raise SystemExit("NSIS did not supply a PE uninstaller")
shutil.copyfile(source, output)
