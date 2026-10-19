#!/bin/sh
set -eu

probe_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
swift build --package-path "$probe_root" --product kumo-autofill-probe
probe_bin_dir=$(swift build --package-path "$probe_root" --show-bin-path)
probe_app="$probe_root/.build/Kumo AutoFill Probe.app"
mkdir -p "$probe_app/Contents/MacOS"
cp "$probe_bin_dir/kumo-autofill-probe" "$probe_app/Contents/MacOS/kumo-autofill-probe"
cat > "$probe_app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>kumo-autofill-probe</string>
    <key>CFBundleIdentifier</key><string>org.kumo.autofill-probe</string>
    <key>CFBundleName</key><string>Kumo AutoFill Probe</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
codesign --force --sign - "$probe_app"
printf '%s\n' "$probe_app"
