#!/usr/bin/env bash
# Builds the KDBX fixtures with KeePassXC itself, so the import tests read files a
# real KeePass client wrote. Needs keepassxc-cli (apt install keepassxc).
# Usage: core/strata-core/tests/fixtures/kdbx/make.sh  (writes next to itself)
set -euo pipefail
cd "$(dirname "$0")"

# A field value just over the vault's 64 KiB limit (spec §8.2).
big=$(head -c 70000 /dev/zero | tr '\0' 'x')
source=$(mktemp)
trap 'rm -f "$source"' EXIT
sed "s/@BIG@/$big/" source.xml > "$source"

rm -f keepassxc.kdbx keepassxc-keyfile.kdbx keyfile.key
# keepassxc-cli asks for the new password twice.
printf 'fixture-password\nfixture-password\n' |
    keepassxc-cli import -q -p "$source" keepassxc.kdbx
# The same contents, opened by a password and a key file together.
head -c 64 /dev/urandom > keyfile.key
printf 'fixture-password\nfixture-password\n' |
    keepassxc-cli import -q -p --set-key-file keyfile.key "$source" keepassxc-keyfile.kdbx
ls -l keepassxc.kdbx keepassxc-keyfile.kdbx keyfile.key
