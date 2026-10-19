#!/bin/bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$task_root/scripts/prepare-sparkle.py" --verify
build_path="$task_root/build/updater-native"
mkdir -p "$build_path"
xcrun swiftc -O -target arm64-apple-macos13.0 -parse-as-library -module-name KumoUpdater \
    -F "$task_root/build/sparkle" -framework Sparkle -framework AppKit -framework Security \
    -Xlinker -rpath -Xlinker '@executable_path/../Frameworks' \
    "$task_root/native/updater/Sources/UpdaterPolicy.swift" \
    "$task_root/native/updater/Sources/main.swift" -o "$build_path/KumoUpdater"
echo "$build_path"
