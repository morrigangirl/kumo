#!/bin/sh
set -eu

test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_build_dir=$(mktemp -d "${TMPDIR:-/tmp}/kumo-native-pairing.XXXXXX")
trap 'rm -rf "$test_build_dir"' EXIT HUP INT TERM
test_sdk=${KUMO_TEST_SDK:-$(xcrun --sdk macosx --show-sdk-path)}

xcrun clang++ -std=c++20 -Wall -Wextra -Werror -isysroot "$test_sdk" \
  "$test_root/native/chromium/kumo_pairing_geometry.cc" \
  "$test_root/tests/native-pairing-geometry.cc" \
  -o "$test_build_dir/native-pairing-geometry-tests"
"$test_build_dir/native-pairing-geometry-tests"

xcrun clang++ -std=c++20 -fobjc-arc -Wall -Wextra -Werror \
  -isysroot "$test_sdk" -mmacosx-version-min=13.0 \
  "$test_root/native/chromium/kumo_pairing_geometry.cc" \
  "$test_root/native/chromium/kumo_pairing_panel.mm" \
  "$test_root/tests/native-pairing-panel.mm" \
  -framework AppKit -framework CoreGraphics \
  -o "$test_build_dir/native-pairing-panel-tests"
"$test_build_dir/native-pairing-panel-tests"
