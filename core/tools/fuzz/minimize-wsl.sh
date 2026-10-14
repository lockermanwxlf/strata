#!/usr/bin/env bash
# Minimizes what a long fuzzing run found (~/strata-corpus, see run-wsl.sh) together
# with the committed corpora into core/fuzz/corpus/<target>, ready to commit: the
# smallest set of inputs that still covers everything they cover. From Windows:
#
#   wsl -d Ubuntu -- bash /mnt/d/src/strata/core/tools/fuzz/minimize-wsl.sh
set -euo pipefail
source "$HOME/.cargo/env"
core="$(cd "$(dirname "$0")/../.." && pwd)"
corpus="$HOME/strata-corpus"
export CARGO_TARGET_DIR="$HOME/strata-fuzz-target"
cd "$core"
for t in $(cargo fuzz list); do
  work="$(mktemp -d)"
  mkdir -p "$work/all" "$work/min"
  [ -d "$corpus/$t" ] && cp -n "$corpus/$t"/* "$work/all/" 2>/dev/null || true
  [ -d "fuzz/corpus/$t" ] && cp -n "fuzz/corpus/$t"/* "$work/all/" 2>/dev/null || true
  # -merge=1 keeps only inputs that add coverage, smallest first.
  cargo fuzz run "$t" "$work/min" "$work/all" -- -merge=1 >"$work/log" 2>&1 \
      || { echo "$t: merge failed"; tail -5 "$work/log"; exit 1; }
  rm -rf "fuzz/corpus/$t"
  mkdir -p "fuzz/corpus/$t"
  cp "$work/min"/* "fuzz/corpus/$t/"
  echo "$t: $(ls "$work/all" | wc -l) inputs -> $(ls "fuzz/corpus/$t" | wc -l)"
  rm -rf "$work"
done
