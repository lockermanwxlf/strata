#!/usr/bin/env bash
# Tests the Linux platform protectors against real services: a software TPM (swtpm)
# and a Secret Service daemon (gnome-keyring) on a private D-Bus session.
#
# Needs: libtss2-dev swtpm swtpm-tools gnome-keyring libdbus-1-dev pkg-config dbus.
# Runs clippy and the whole test suite with both services up, so the Linux-only
# code is linted and tested. Usage: core/tools/linux-protectors.sh [cargo test args]
set -euo pipefail

core="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
# On a Windows checkout (WSL), keep Linux build output out of the Windows target dir.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/strata-target}"

tpm_state="$(mktemp -d)"
trap 'kill "$swtpm_pid" 2>/dev/null || true; rm -rf "$tpm_state"' EXIT
swtpm socket --tpm2 --tpmstate dir="$tpm_state" \
    --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
    --flags not-need-init,startup-clear &
swtpm_pid=$!
sleep 1
export STRATA_TPM_TCTI="swtpm:host=127.0.0.1,port=2321"

cd "$core"
# A throwaway login keyring, unlocked with a throwaway password, on a private bus.
dbus-run-session -- bash -c '
    set -e
    printf "test-keyring-password" | gnome-keyring-daemon --unlock --components=secrets >/dev/null
    cargo clippy -p strata-core --all-targets -- -D warnings
    PROPTEST_CASES="${PROPTEST_CASES:-16}" cargo test -p strata-core "$@"
' _ "$@"
