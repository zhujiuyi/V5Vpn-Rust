#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
project_root="$(pwd -P)"
cargo build --locked --release --target aarch64-apple-darwin --bins

release_dir="$project_root/target/aarch64-apple-darwin/release"
stage="$(mktemp -d "$release_dir/v5vpn-app.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT HUP INT TERM
bundle="$stage/V5VPN.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
cp "$release_dir/v5vpn-desktop" "$bundle/Contents/MacOS/"
cp "$release_dir/v5vpn-nc-helper" "$bundle/Contents/MacOS/"
cp assets/v5vpn.png "$bundle/Contents/Resources/"
./support/bundle-macos-runtime.sh "$bundle/Contents/Resources/NC"
package_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
iconset="$stage/V5VPN.iconset"
mkdir -p "$iconset"
for points in 16 32 128 256 512; do
  /usr/bin/sips -s format png -z "$points" "$points" assets/v5vpn.png --out "$iconset/icon_${points}x${points}.png" >/dev/null
  pixels=$((points * 2))
  /usr/bin/sips -s format png -z "$pixels" "$pixels" assets/v5vpn.png --out "$iconset/icon_${points}x${points}@2x.png" >/dev/null
done
/usr/bin/iconutil -c icns "$iconset" -o "$bundle/Contents/Resources/AppIcon.icns"
cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
  <key>CFBundleDisplayName</key><string>V5VPN</string>
  <key>CFBundleExecutable</key><string>v5vpn-desktop</string>
  <key>CFBundleIdentifier</key><string>io.github.zhujiuyi.V5Vpn-Rust</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>V5VPN</string>
  <key>CFBundleIconFile</key><string>AppIcon.icns</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$package_version</string>
  <key>CFBundleVersion</key><string>$package_version</string>
  <key>LSMinimumSystemVersion</key><string>27.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
plutil -lint "$bundle/Contents/Info.plist"
codesign --force --sign - "$bundle/Contents/MacOS/v5vpn-nc-helper"
codesign --force --sign - "$bundle"
codesign --verify --deep --strict "$bundle"

output="$release_dir/V5VPN.app"
rm -rf "$output.previous"
if [ -d "$output" ]; then mv "$output" "$output.previous"; fi
mv "$bundle" "$output"
printf 'macOS 应用包已生成：%s\n' "$output"
