#!/bin/sh
# Select Apple's full macOS SDK/compiler for GN's standalone helper bootstrap.
# Chromium itself keeps the pinned LLVM toolchain selected by its GN files.
set -eu
KUMO_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
export CC="$(xcrun --find clang)"
export CXX="$(xcrun --find clang++)"
if [ "$#" -eq 0 ]; then
  set -- build
fi
# Keep each locked engine version in its own prepared source workspace.
# An explicit --work-dir later in "$@" still overrides this default.
KUMO_SOURCE_WORK_DIRECTORY=$(python3 - "$KUMO_SCRIPT_DIRECTORY/../config/source-lock.json" <<'PY'
import json
from pathlib import Path
import re
import sys

lock_path = Path(sys.argv[1]).resolve()
version = json.loads(lock_path.read_text())["chromiumVersion"]
if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version):
    raise SystemExit("Invalid locked Chromium version")
print(lock_path.parents[1] / "build" / ("source-" + version))
PY
)
exec python3 "$KUMO_SCRIPT_DIRECTORY/source.py" --work-dir "$KUMO_SOURCE_WORK_DIRECTORY" "$@"
