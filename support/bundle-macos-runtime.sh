#!/bin/sh
set -eu

runtime="$1"
sw_root="$(cd "$(brew --prefix strongswan)" && pwd -P)"
ssl_root="$(cd "$(brew --prefix openssl@4)" && pwd -P)"
mkdir -p "$runtime/bin" "$runtime/lib/plugins" "$runtime/lib/ossl-modules" "$runtime/licenses" "$runtime/build-recipes"
cp "$sw_root/libexec/ipsec/charon" "$runtime/bin/charon"
cp "$sw_root/lib/ipsec/libstrongswan.0.dylib" "$sw_root/lib/ipsec/libcharon.0.dylib" "$runtime/lib/"
cp "$ssl_root/lib/libcrypto.4.dylib" "$runtime/lib/"
for plugin in openssl kdf nonce kernel-pfkey kernel-pfroute socket-default vici; do
  cp "$sw_root/lib/ipsec/plugins/libstrongswan-$plugin.so" "$runtime/lib/plugins/"
done
cp "$ssl_root/lib/ossl-modules/legacy.dylib" "$runtime/lib/ossl-modules/"
cp "$sw_root/LICENSE" "$runtime/licenses/strongSwan-LICENSE.txt"
cp "$sw_root/COPYING" "$runtime/licenses/strongSwan-COPYING.txt"
cp "$ssl_root/LICENSE.txt" "$runtime/licenses/OpenSSL-LICENSE.txt"
cp "$sw_root/.brew/strongswan.rb" "$ssl_root/.brew/openssl@4.rb" "$runtime/build-recipes/"
cp "$(brew --repository)/LICENSE.txt" "$runtime/licenses/Homebrew-LICENSE.txt"
HOMEBREW_NO_AUTO_UPDATE=1 brew info --json=v2 strongswan openssl@4 > "$runtime/build-recipes/homebrew-formulae.json"

# All non-system Mach-O dependencies must resolve inside this runtime.
for binary in "$runtime/bin/charon" "$runtime/lib/"*.dylib "$runtime/lib/plugins/"*.so "$runtime/lib/ossl-modules/"*.dylib; do
  case "$binary" in
    */bin/*) relative='../lib' ;;
    */plugins/*|*/ossl-modules/*) relative='..' ;;
    *) relative='.' ;;
  esac
  otool -L "$binary" | awk 'NR > 1 && $1 ~ /^\/opt\/homebrew\// {print $1}' |
  while IFS= read -r dependency; do
    xcrun install_name_tool -change "$dependency" "@loader_path/$relative/$(basename "$dependency")" "$binary"
  done
  case "$binary" in *.dylib) xcrun install_name_tool -id "@rpath/$(basename "$binary")" "$binary" ;; esac
done

# Upstream's loader stat()s its compiled plugin directory before dlopen().
# Relocate that string without changing Mach-O section sizes; charon runs with
# this runtime's lib directory as its working directory.
V5VPN_PLUGIN_DIR="$sw_root/lib/ipsec/plugins" /usr/bin/perl -0777 -i -pe '
  BEGIN { $old = $ENV{V5VPN_PLUGIN_DIR}; $count = 0; }
  $count += s/\Q$old\E\x00/"plugins" . ("\x00" x (length($old) - 7 + 1))/ge;
  END { die "strongSwan plugin directory was not found\n" unless $count; }
' "$runtime/lib/libstrongswan.0.dylib"

cat > "$runtime/openssl.cnf" <<'CONF'
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
[default_sect]
activate = 1
CONF

for binary in "$runtime/bin/charon" "$runtime/lib/"*.dylib "$runtime/lib/plugins/"*.so "$runtime/lib/ossl-modules/"*.dylib; do
  if otool -L "$binary" | awk 'NR > 1 {print $1}' | /usr/bin/grep -q '^/opt/homebrew/'; then
    printf 'Unrelocated dependency: %s\n' "$binary" >&2
    exit 1
  fi
  codesign --force --sign - "$binary"
  codesign --verify --strict "$binary"
done
printf 'Bundled NC runtime: %s\n' "$runtime"
