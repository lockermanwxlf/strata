# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "argon2-cffi==25.1.0",
#   "cbor2==6.1.5",
#   "cryptography==50.0.2",
#   "kyber-py==1.2.0",
#   "mnemonic==0.21",
#   "pynacl==1.6.0",
# ]
# ///
"""Writes fuzz seed corpora (core/fuzz/seeds/<target>/) from the frozen test vectors.

Real, valid files get libFuzzer past magic bytes and length checks immediately, so
the fuzzers spend their time on the interesting paths. Run from the repository root
after the vectors change:

    uv run core/tools/fuzz/make_seeds.py
"""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "core" / "tools" / "vectors"))
import check  # noqa: E402  (only definitions run on import)

OUT = ROOT / "core" / "fuzz" / "seeds"
h = bytes.fromhex


def write(target, name, data):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    v = check.load("files.json")

    # envelopes: the first byte picks the parser (see fuzz_targets/envelopes.rs).
    write("envelopes", "vault_info", bytes([0]) + h(v["vault_info"]["file"]))
    for s in v["slots"]:
        write("envelopes", f"slot{s['kind']}", bytes([2 if s["kind"] == 4 else 1]) + h(s["file"]))
    for e in v["epochs"]:
        write("envelopes", f"epoch{e['epoch']}", bytes([3]) + h(e["file"]))
    write("envelopes", "event", bytes([4]) + h(v["event"]["file"]))
    write("envelopes", "snapshot", bytes([5]) + h(v["snapshot"]["file"]))

    b = v["event"]["body"]
    event_body = check.cbor2.dumps(
        {1: b["hlc"], 2: check.clock_cbor(b["clock"]), 3: h(b["prev_hash"]), 4: [check.op_cbor(o) for o in b["ops"]]},
        canonical=True,
    )
    write("bodies", "event", bytes([0]) + event_body)
    b = v["snapshot"]["body"]
    snapshot_body = check.cbor2.dumps(
        {
            1: [[h(c), s, h(x)] for c, s, x in b["watermark"]],
            2: [check.clock_cbor(c) for c in b["clocks"]],
            3: [[h(o["client_id"]), o["seq"], o["op_index"], o["hlc"], o["vc_index"], check.op_cbor(o["op"])] for o in b["ops"]],
        },
        canonical=True,
    )
    write("bodies", "snapshot", bytes([1]) + snapshot_body)

    write("padding", "event_body", check.pad(event_body))
    for i, path in enumerate([
        "strata-vault",
        "epochs/00000001-" + "a0" * 16 + ".epoch",
        "slots/" + "70" * 16 + ".slot",
        "events/" + "a0" * 16 + "-0000000000000001.evt",
        "snapshots/" + "74" * 16 + ".snap",
    ]):
        write("names", f"path{i}", path.encode())
    write("reader", "header", bytes([20]) + bytes(range(64)))
    print(f"wrote {sum(1 for p in OUT.rglob('*') if p.is_file())} seeds to {OUT}")


if __name__ == "__main__":
    main()
