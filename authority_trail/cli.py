"""Command line: demo, verify, memo, tamper, anchor-*, keygen.

Exit codes for verify and memo: 0 clean, 1 integrity failed, 3 authority findings, 2 usage or read error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import VERSION, anchor, demo as demo_mod, memo as memo_mod, ots
from .keys import Party, fingerprint
from .memo import safe
from .spec import HEX64
from .verify import exit_code, verify_bundle


MAX_BUNDLE_BYTES = 20 * 1024 * 1024


def _load(path):
    try:
        if os.path.getsize(path) > MAX_BUNDLE_BYTES:
            raise ValueError("file larger than 20 MB")
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        print(f"cannot read {path}: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)


def _save(path, bundle):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=1, ensure_ascii=False)
        f.write("\n")


def _head(bundle):
    if not bundle.get("entries"):
        print("the log is empty", file=sys.stderr)
        sys.exit(2)
    e = bundle["entries"][-1]
    return e["seq"], e["hash"]


def cmd_demo(a):
    os.makedirs(a.out, exist_ok=True)
    trail, P, outcomes = demo_mod.build()
    good = os.path.join(a.out, "trail.json")
    trail.save(good)
    rogue = demo_mod.rogue_variant(trail, P)
    rogue.save(os.path.join(a.out, "trail_rogue_operator.json"))
    with open(os.path.join(a.out, "PRINCIPAL_KEY_ID.txt"), "w", encoding="utf-8") as f:
        f.write(P["principal"].key_id + "\n")
    print("Scenario (all names are fictional; keys are throwaway and not saved):")
    for label, verdict, reasons in outcomes:
        mark = {"IN_AUTHORITY": "ok     ", "GRANT_OK": "ok     ", "REVOCATION_EFFECTIVE": "ok     "}.get(verdict, "REFUSED")
        print(f"  [{mark}] {label}" + (f"  <- {reasons[0].split(':')[0]}" if reasons else ""))
    print(f"\nWrote {good}, trail_rogue_operator.json and PRINCIPAL_KEY_ID.txt in {a.out}")
    print(f"Pin this root key when you verify:  --pin {P['principal'].key_id}")
    return 0


def _verify(a):
    bundle = _load(a.bundle)
    return bundle, verify_bundle(bundle, pinned_keys=a.pin, network=a.network, eth_rpc=a.eth_rpc,
                                 expect_head=a.expect_head, require_anchor=a.require_anchor)


def cmd_verify(a):
    bundle, rep = _verify(a)
    if a.json:
        print(json.dumps(rep, indent=1, ensure_ascii=False))
        return exit_code(rep)
    s = rep["summary"]
    print(f"RESULT: {rep['status']}")
    print(f"  entries {rep['entries']}; hash chain {'intact' if rep['chain']['ok'] else 'BROKEN'}")
    for p in rep["chain"]["problems"]:
        print(f"  !! {safe(p['code'])} at entry {p['seq']} {safe(p['detail'])}")
    if s:
        print(f"  requested actions {s['actions']}: {s['in_authority']} within limits, "
              f"{s['blocked_as_expected']} outside limits and refused, "
              f"{s['allowed_outside_authority']} outside limits but not refused")
    for an in rep["anchors"]:
        print(f"  anchor {an['method']} entry {an['seq']}: {an['status']}"
              + ("" if an["status"] == "CONFIRMED" else "  (not counted as coverage)"))
    for f in rep["findings"]:
        if f["severity"] != "INFO":
            print(f"  [{safe(f['severity'])}] {safe(f['code'])} at entry {f['seq']}: {safe(f['detail'], 600)}")
    if not a.pin:
        print("  note: no --pin given, so the root key is not checked against any outside source")
    if not a.expect_head and not rep["anchors"]:
        print("  note: no anchor and no --expect-head, so a rebuilt log could not be told from the original")
    return exit_code(rep)


def cmd_memo(a):
    bundle, rep = _verify(a)
    sys.stdout.reconfigure(encoding="utf-8")
    print(memo_mod.render(rep, bundle), end="")
    return exit_code(rep)


def cmd_tamper(a):
    bundle = _load(a.bundle)
    fn = demo_mod.tamper_rehash if a.mode == "rehash" else demo_mod.tamper_amount
    _save(a.out, fn(bundle))
    print(f"wrote {a.out}: one recorded payment amount changed ({'hashes recomputed' if a.mode == 'rehash' else 'hashes left alone'})")
    return 0


def cmd_anchor_stamp(a):
    bundle = _load(a.bundle)
    seq, h = _head(bundle)
    digest = anchor.head_digest(seq, h)
    print(f"sending only this 32-byte hash to public OpenTimestamps calendars: {digest.hex()}")
    proof = ots.stamp(digest, a.calendar or None)
    bundle.setdefault("anchors", []).append(anchor.new_ots_anchor(seq, h, proof))
    _save(a.bundle, bundle)
    print(f"anchored entry {seq} (PENDING until Bitcoin confirms; run anchor-upgrade in a few hours)")
    return 0


def cmd_anchor_upgrade(a):
    bundle = _load(a.bundle)
    total = 0
    for an in bundle.get("anchors", []):
        if an.get("method") != "opentimestamps":
            continue
        new, n, skipped = ots.upgrade(ots.unb64(an["ots_b64"]))
        if n:
            an["ots_b64"] = ots.b64(new)
            total += n
        if skipped:
            print(f"skipped calendar hosts that are not on the built-in list: {sorted(set(skipped))}")
    _save(a.bundle, bundle)
    print(f"completed {total} pending attestation(s)" if total else "nothing to complete yet (Bitcoin has not confirmed)")
    return 0


def cmd_anchor_export(a):
    bundle = _load(a.bundle)
    os.makedirs(a.dir, exist_ok=True)
    n = 0
    for an in bundle.get("anchors", []):
        if not isinstance(an, dict) or an.get("method") != "opentimestamps":
            continue
        if type(an.get("seq")) is not int or not (isinstance(an.get("head_hash"), str) and HEX64.match(an["head_hash"])):
            print("skipping an anchor with an invalid seq or head_hash", file=sys.stderr)
            continue
        name = f"head_{an['seq']}.txt"
        with open(os.path.join(a.dir, name), "w", encoding="utf-8", newline="") as f:
            f.write(anchor.head_text(an["seq"], an["head_hash"]))
        with open(os.path.join(a.dir, name + ".ots"), "wb") as f:
            f.write(ots.unb64(an["ots_b64"]))
        n += 1
        print(f"wrote {name} and {name}.ots; check with the official client:  ots verify {name}.ots")
    return 0 if n else 2


def cmd_anchor_eth_data(a):
    bundle = _load(a.bundle)
    seq, h = _head(bundle)
    print(f"entry {seq}\nhead  {h}\ndata  {anchor.eth_expected_data(seq, h)}")
    print("Send a 0-value transaction to your own address on the test network with that data (contrib/eth_send_anchor.py does this).")
    return 0


def cmd_anchor_eth_record(a):
    bundle = _load(a.bundle)
    seq, h = _head(bundle)
    bundle.setdefault("anchors", []).append(anchor.new_eth_anchor(seq, h, a.tx, a.chain_id, a.network_name))
    _save(a.bundle, bundle)
    print(f"recorded an {a.network_name} anchor for entry {seq}; verify with: verify {a.bundle} --network")
    return 0


def cmd_head(a):
    bundle = _load(a.bundle)
    seq, h = _head(bundle)
    print(f"{seq}:{h}")
    print("Keep this line somewhere the log operator cannot edit. Later: verify <bundle> --expect-head " + f"{seq}:{h}", file=sys.stderr)
    return 0


def cmd_keygen(a):
    p = Party(a.name)
    try:
        p.save_seed(a.out)
    except FileExistsError:
        print(f"{a.out} already exists; refusing to overwrite a key file", file=sys.stderr)
        return 2
    print(f"wrote private seed to {a.out} (keep it secret)\npublic key {p.public_hex}\nkey id     {p.key_id}\nfingerprint {fingerprint(p.public_hex)}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="authority_trail", description="Verifiable records of delegated authority for AI agent actions.")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run the fictional scenario and write bundles")
    d.add_argument("--out", default="demo_out")
    d.set_defaults(fn=cmd_demo)

    for name, fn in (("verify", cmd_verify), ("memo", cmd_memo)):
        v = sub.add_parser(name, help="verify a bundle" if name == "verify" else "print the full authority memo")
        v.add_argument("bundle")
        v.add_argument("--pin", action="append", default=[], help="root key id or public key (hex) you trust from an outside source; repeatable")
        v.add_argument("--network", action="store_true", help="look up anchors on public services")
        v.add_argument("--eth-rpc", help="Ethereum JSON-RPC URL you choose for anchor lookups (a bundle cannot choose it)")
        v.add_argument("--expect-head", help="SEQ:HASH you saved earlier (see the head command); fail if the log does not contain it")
        v.add_argument("--require-anchor", action="store_true", help="fail unless an anchor is confirmed against an outside ledger (implies --network)")
        if name == "verify":
            v.add_argument("--json", action="store_true")
        v.set_defaults(fn=fn)

    t = sub.add_parser("tamper", help="write an edited copy of a bundle to show detection")
    t.add_argument("bundle")
    t.add_argument("--out", required=True)
    t.add_argument("--mode", choices=["amount", "rehash"], default="amount")
    t.set_defaults(fn=cmd_tamper)

    h = sub.add_parser("head", help="print SEQ:HASH of the log head, to keep somewhere the operator cannot edit")
    h.add_argument("bundle")
    h.set_defaults(fn=cmd_head)

    s = sub.add_parser("anchor-stamp", help="anchor the log head with OpenTimestamps (sends only a hash)")
    s.add_argument("bundle")
    s.add_argument("--calendar", action="append")
    s.set_defaults(fn=cmd_anchor_stamp)
    u = sub.add_parser("anchor-upgrade", help="complete pending OpenTimestamps proofs once Bitcoin has confirmed (contacts only well-known calendars)")
    u.add_argument("bundle")
    u.set_defaults(fn=cmd_anchor_upgrade)
    e = sub.add_parser("anchor-export", help="write head_N.txt and head_N.txt.ots for the official ots client")
    e.add_argument("bundle")
    e.add_argument("--dir", default="anchor_files")
    e.set_defaults(fn=cmd_anchor_export)
    ed = sub.add_parser("anchor-eth-data", help="print the transaction data to anchor the head on an Ethereum test network")
    ed.add_argument("bundle")
    ed.set_defaults(fn=cmd_anchor_eth_data)
    er = sub.add_parser("anchor-eth-record", help="record the transaction hash of an Ethereum anchor")
    er.add_argument("bundle")
    er.add_argument("--tx", required=True)
    er.add_argument("--chain-id", type=int, default=11155111)
    er.add_argument("--network-name", default="sepolia")
    er.set_defaults(fn=cmd_anchor_eth_record)
    k = sub.add_parser("keygen", help="create a signing key")
    k.add_argument("--name", required=True)
    k.add_argument("--out", required=True)
    k.set_defaults(fn=cmd_keygen)

    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:  # redirected output on Windows can default to a legacy code page
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
