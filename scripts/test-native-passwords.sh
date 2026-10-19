#!/bin/sh
set -eu

test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_build_dir=$(mktemp -d "${TMPDIR:-/tmp}/kumo-native-passwords.XXXXXX")
trap 'rm -rf "$test_build_dir"' EXIT HUP INT TERM

# Use the SDK compatible with the selected Xcode compiler. A caller may supply
# another matching public SDK explicitly without changing system settings.
test_sdk=${KUMO_TEST_SDK:-$(xcrun --sdk macosx --show-sdk-path)}
xcrun clang++ -std=c++20 -fobjc-arc -Wall -Wextra -Werror \
  -isysroot "$test_sdk" -mmacosx-version-min=13.0 \
  "$test_root/native/chromium/kumo_password_panel.mm" \
  "$test_root/tests/native-password-panel.mm" \
  -framework AppKit -o "$test_build_dir/native-password-panel-tests"
"$test_build_dir/native-password-panel-tests"
