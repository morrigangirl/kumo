#!/bin/bash
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
build_path="$task_root/build/phishing-native"
xcrun swift build --package-path "$task_root/native/phishing" --scratch-path "$build_path" --configuration release --product KumoPhishingHost
task_bin_path="$(xcrun swift build --package-path "$task_root/native/phishing" --scratch-path "$build_path" --configuration release --show-bin-path)"
cp "$task_bin_path/KumoPhishingHost" "$build_path/KumoPhishingHost"
echo "$build_path/KumoPhishingHost"
