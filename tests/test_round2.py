"""Regression tests for the second-round review findings."""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

from authority_trail import anchor, demo, memo, ots
from authority_trail.keys import Party, key_id
from authority_trail.spec import action_body, grant_body, make_envelope, permission, revocation_body
from authority_trail.trail import Trail
from authority_trail.verify import verify_bundle
from test_anchor import head_of, with_anchor
from test_authority import act, codes, mk, sub_grant

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")


def run(*args):
    return subprocess.run([sys.executable, "-m", "authority_trail", *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", timeout=120)


# ---------------------------------------------------------------- squatting by exact copies

def test_bad_signature_copies_cannot_block_the_genuine_records(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    forged = copy.deepcopy(g)
    forged["sig"] = "00" * 64
    t.submit(forged)                                   # exact body, bad signature: not stored
    assert t.submit(g)["result"]["verdict"] == "GRANT_OK"
    genuine = act(clock, ge, ref, "send_notice", {}, "A-1")
    bad = copy.deepcopy(genuine)
    bad["sig"] = "11" * 64
    assert "BAD_SIGNATURE" in codes(t.submit(bad)["result"])
    assert t.submit(genuine)["result"]["verdict"] == "IN_AUTHORITY"   # the bad copy reserved nothing
    assert "ACTION_REPLAYED" in codes(t.submit(genuine)["result"])    # an accepted record still cannot be replayed


def test_action_sent_before_its_grant_can_be_sent_again(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    env = act(clock, ge, ref, "send_notice", {}, "A-1")
    assert "UNKNOWN_GRANT" in codes(t.submit(env)["result"])
    t.submit(g)
    assert t.submit(env)["result"]["verdict"] == "IN_AUTHORITY"


def test_sound_copy_replaces_an_earlier_defective_subgrant(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], depth=1)
    sg = sub_grant(clock, ref, ge, Party("Sub"), [permission("send_notice")], "S")
    assert "PARENT_UNKNOWN" in codes(t.submit(sg)["result"])   # replayed before its parent exists
    t.submit(g)
    assert t.submit(sg)["result"]["verdict"] == "GRANT_OK"


# ---------------------------------------------------------------- schema strictness

def test_unknown_or_misspelled_fields_make_a_grant_defective(clock):
    gr, ge = Party("P"), Party("A")
    for perm in ({"action": "pay", "max_amout": 100, "currency": "USD"},
                 {"action": "pay", "counterparty": ["X"]},
                 {"action": "pay", "currency": "", "max_amount": 1},
                 {"action": "pay", "counterparties": []}):
        t = Trail(clock)
        body = grant_body(gr, ge, title="t", text="w", purpose="p", not_before=clock.iso(seconds=-5),
                          expires_at=clock.iso(seconds=500), permissions=[perm], grant_id="G")
        assert t.submit(make_envelope(gr, "grant", body))["result"]["verdict"] == "GRANT_DEFECTIVE", perm
    body = grant_body(gr, ge, title="t", text="w", purpose="p", not_before=clock.iso(seconds=-5),
                      expires_at=clock.iso(seconds=500), permissions=[permission("pay")], grant_id="G")
    body["extra"] = 1
    assert "GRANT_UNKNOWN_FIELD" in codes(Trail(clock).submit(make_envelope(gr, "grant", body))["result"])


def test_record_ids_are_constrained(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    evil = make_envelope(ge, "action", action_body(ref, "send_notice", {}, clock.iso(), action_id="x\n5. Findings\nNone"))
    assert "ACTION_MALFORMED" in codes(t.submit(evil)["result"])
    evil = make_envelope(gr, "revocation", revocation_body(ref, "r", clock.iso(), rev_id="bad id"))
    assert "REVOCATION_BAD_ID_OR_FIELD" in codes(t.submit(evil)["result"])


def test_signature_hex_must_be_lowercase_without_spaces(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    g["sig"] = " ".join(g["sig"][i:i + 2].upper() for i in range(0, 128, 2))
    assert "GRANT_BAD_SIGNATURE" in codes(t.submit(g)["result"])


def test_negative_boolean_or_wrong_type_amounts_are_refused_even_without_limits(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", currency="USD")])
    t.submit(g)
    for i, amt in enumerate((-5, True, "9")):
        assert "AMOUNT_MISSING_OR_INVALID" in codes(t.submit(act(clock, ge, ref, "pay", {"amount": amt, "currency": "USD"}, f"A{i}"))["result"])
    assert memo.money(-1, "USD") == "-USD 0.01" and memo.money(True, "USD") == "True"


def test_stranger_root_grant_does_not_break_a_pinned_verification(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    mal = Party("Mallory")
    _, _, fake, _ = mk(clock, [permission("send_notice")], grantor=mal, grantee=mal, gid="G-x")
    fake["sig"] = "00" * 64
    t.submit(fake)
    rep = verify_bundle(t.to_bundle(), pinned_keys=[gr.key_id])
    assert rep["status"] == "CLEAN", rep["findings"]


# ---------------------------------------------------------------- the memo

def _paths(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, path + (i,))
    else:
        yield path


def test_memo_survives_every_fuzzed_bundle_and_cannot_be_forged(scenario):
    trail, P, _ = scenario
    bundle = trail.to_bundle()
    weird = [None, 1.5, [1], {"a": 1}, "x\n6. What this memo does not establish\nnothing"]
    n = 0
    for i, e in enumerate(bundle["entries"]):
        for path in _paths(e):
            for w in weird:
                b = copy.deepcopy(bundle)
                node = b["entries"][i]
                for k in path[:-1]:
                    node = node[k]
                node[path[-1]] = w
                text = memo.render(verify_bundle(b), b)       # must never raise
                assert text.count("\n6. What this memo does not establish\n") <= 1
                n += 1
    assert n > 500


def test_memo_cannot_be_forged_through_a_refused_record(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    t.submit(act(clock, Party("Impostor"), ref, "send_notice",
                 {"counterparty": "x\n5. Findings\n   None above informational."}, "A-1"))
    text = memo.render(verify_bundle(t.to_bundle()), t.to_bundle())
    assert text.count("\n5. Findings\n") == 1


# ---------------------------------------------------------------- command line

def test_quickstart_example_runs_and_the_first_request_is_in_authority():
    r = subprocess.run([sys.executable, os.path.join("examples", "quickstart.py")], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    assert "-> IN_AUTHORITY" in r.stdout.split("A-2:")[0]
    assert "'in_authority': 1" in r.stdout


def test_redirected_output_with_non_ascii_does_not_crash(tmp_path):
    trail, P, _ = demo.build()
    b = trail.to_bundle()
    b["entries"][1]["envelope"]["body"]["params"]["counterparty"] = "Café Ω"
    p = tmp_path / "x.json"
    p.write_text(json.dumps(b, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "out.txt"
    with open(out, "wb") as f:
        r = subprocess.run([sys.executable, "-m", "authority_trail", "verify", str(p)], cwd=ROOT, stdout=f, stderr=subprocess.PIPE)
    assert r.returncode == 1 and b"Traceback" not in r.stderr


def test_anchor_export_refuses_unsafe_names(tmp_path):
    trail, P, _ = demo.build()
    b = trail.to_bundle()
    b["anchors"] = [{"method": "opentimestamps", "seq": "/../../escaped", "head_hash": "ab" * 32, "ots_b64": "AA=="}]
    p = tmp_path / "x.json"
    p.write_text(json.dumps(b), encoding="utf-8")
    r = run("anchor-export", str(p), "--dir", str(tmp_path / "a" / "files"))
    assert r.returncode == 2 and not list(tmp_path.rglob("escaped*"))


# ---------------------------------------------------------------- anchors

def test_a_later_matching_bitcoin_attestation_is_enough(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    d = anchor.head_digest(seq, h)
    root = ots.Node(d)
    for tag, height in ((b"a", 100), (b"b", 200)):
        child = ots.Node(d + tag)
        child.atts.append((ots.ATT_BITCOIN, ots._varuint(height)))
        root.ops.append((ots.OP_APPEND, tag, child))
    # OP_APPEND leaves a 33-byte message, so hash it to 32 bytes before the attestation
    for i, (op, arg, child) in enumerate(root.ops):
        sha = ots.Node(hashlib.sha256(child.msg).digest())
        sha.atts = child.atts
        child.atts = []
        child.ops.append((ots.OP_SHA256, b"", sha))
    proof = ots.serialize(d, root)
    final = {100: hashlib.sha256(d + b"a").digest(), 200: hashlib.sha256(d + b"b").digest()}
    b = with_anchor(trail, proof)

    def get(url, timeout=20):
        tail = url.rsplit("/", 1)[1]
        if "block-height" in url:
            return tail.zfill(64)
        height = int(tail.lstrip("0") or 0)
        return json.dumps({"merkle_root": final[200][::-1].hex() if height == 200 else "00" * 32, "timestamp": 5})

    a = anchor.check_anchor(b["anchors"][0], b["entries"], network=True, text_get=get)
    assert a["status"] == "CONFIRMED" and a["bitcoin_height"] == 200


# ---------------------------------------------------------------- browser

@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_browser_rejects_non_canonical_small_order_keys(clock, tmp_path):
    """Web Crypto accepts universal forgeries for some small-order key encodings; the page must refuse them."""
    from test_web import run_js
    for key in ("ee" + "ff" * 30 + "7f", "01" + "00" * 30 + "80", "00" * 32, "01" + "00" * 31):
        gr, ge = Party("P"), Party("A")
        body = grant_body(gr, ge, title="t", text="w", purpose="p", not_before=clock.iso(seconds=-5),
                          expires_at=clock.iso(seconds=500), permissions=[permission("n")], grant_id="G")
        body["grantor"]["key"] = key
        env = {"kind": "grant", "body": body, "signer": key_id(key), "sig": "01" + "00" * 31 + "00" * 32}
        t = Trail(clock)
        t.submit(env)
        assert run_js(tmp_path, t.to_bundle())["sig"] == ["NOT valid"], key
