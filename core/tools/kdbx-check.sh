#!/usr/bin/env bash
# Checks Strata's KeePass export with KeePassXC itself: exports the import fixture
# through the core, then has keepassxc-cli open the file and dump it.
#
# Needs keepassxc-cli (apt install keepassxc), plus what core/tools/linux-protectors.sh
# needs to build the core on Linux. Usage: core/tools/kdbx-check.sh
set -euo pipefail

core="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
# On a Windows checkout (WSL), keep Linux build output out of the Windows target dir.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/strata-target}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export STRATA_KDBX_EXPORT="$work/export.kdbx"

cd "$core"
cargo test -q -p strata-core --lib keepass_import_export_and_back_keeps_everything
printf 'export password\n' | keepassxc-cli export -q -f xml "$STRATA_KDBX_EXPORT" > "$work/export.xml"

fail=0
expect() {
    if grep -qF -- "$1" "$work/export.xml"; then
        echo "ok: $2"
    else
        echo "MISSING: $2 ($1)"
        fail=1
    fi
}
expect '<Value>Bank</Value>' "entry title"
expect '<Value ProtectInMemory="True">bank-password</Value>' "protected password"
expect '<Value ProtectInMemory="True">4711</Value>' "protected custom field"
expect '<Key>Account type</Key>' "custom field"
expect '<Value>a custom field that clashes with url</Value>' "clashing custom field"
expect '<Name>Finance</Name>' "group"
expect '<Name>Cards</Name>' "nested group"
expect '<Key>key.txt</Key>' "attachment"
expect '<IconID>66</IconID>' "icon"
expect '<OverrideURL>cmd://firefox {URL}</OverrideURL>' "override URL"
expect '<Window>*Bank*</Window>' "auto-type association"
expect '<Expires>True</Expires>' "expiry"
expect '<Key>KPXC_DECRYPTION_TIME_PREFERENCE</Key>' "custom data"
expect 'otpauth://totp/Mail' "TOTP"
if grep -qF 'old-bank-password' "$work/export.xml"; then
    echo "UNEXPECTED: history came through"
    fail=1
fi
exit "$fail"
