#!/usr/bin/env bash
# Runs every fuzz target in parallel for N seconds (default 600) under Linux/WSL,
# starting from the committed seeds. Windows can't link the fuzz targets natively
# (see CLAUDE.md, Gotchas). From Windows:
#
#   wsl -d Ubuntu -- bash /mnt/d/src/strata/core/tools/fuzz/run-wsl.sh 600
#
# Needs rustup (nightly) and cargo-fuzz inside WSL. Build output and the growing
# corpora live in the WSL home directory, which is much faster than /mnt/d.
set -u
seconds="${1:-600}"
source "$HOME/.cargo/env"
core="$(cd "$(dirname "$0")/../.." && pwd)"
corpus="$HOME/strata-corpus"
logs="$HOME/strata-fuzz-logs"
export CARGO_TARGET_DIR="$HOME/strata-fuzz-target"
mkdir -p "$corpus" "$logs"
cd "$core"
targets=$(cargo fuzz list)
cargo fuzz build >/dev/null 2>&1 || { echo "cargo fuzz build failed"; exit 1; }
for t in $targets; do
  mkdir -p "$corpus/$t"
  (cargo fuzz run "$t" "$corpus/$t" "fuzz/seeds/$t" -- -max_total_time="$seconds" -print_final_stats=1 \
      > "$logs/$t.log" 2>&1; echo "exit=$?" >> "$logs/$t.log") &
done
wait
status=0
for t in $targets; do
  runs=$(grep -aoE 'stat::number_of_executed_units: [0-9]+' "$logs/$t.log" | grep -oE '[0-9]+$')
  result=$(grep -E '^exit=' "$logs/$t.log")
  echo "$t: $result, $runs runs, corpus $(ls "$corpus/$t" | wc -l)"
  if [ "$result" != "exit=0" ]; then
    status=1
    grep -aE 'panicked|ERROR: |SUMMARY|artifact_prefix|Test unit written' "$logs/$t.log" | head -8
  fi
done
exit $status
