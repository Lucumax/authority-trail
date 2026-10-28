import copy
import hashlib
import json

from authority_trail import anchor, demo, ots
from authority_trail.trail import entry_hash
from authority_trail.verify import verify_bundle


def leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leaves(v, path + (i,))
    else:
        yield path, obj


def mutate(bundle, entry_idx, path):
    b = copy.deepcopy(bundle)
    node = b["entries"][entry_idx]
    for p in path[:-1]:
        node = node[p]
    v = node[path[-1]]
    if isinstance(v, bool):
        node[path[-1]] = not v
    elif isinstance(v, int):
        node[path[-1]] = v + 1
    elif isinstance(v, str):
        node[path[-1]] = v + "x" if v else "x"
    else:
        node[path[-1]] = "x"
    return b


def rehash(b):
    prev = "0" * 64
    for e in b["entries"]:
        e["prev"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    return b


def test_plain_edit_of_every_field_is_detected(scenario, capsys):
    """Mutation test: change each leaf value of each entry, one at a time, leave hashes alone.
    This is a regression guard on the hash chain, not an independent evaluation."""
    trail, _, _ = scenario
    bundle = trail.to_bundle()
    total = missed = 0
    for i, e in enumerate(bundle["entries"]):
        for path, _ in leaves(e):
            m = mutate(bundle, i, path)
            rep = verify_bundle(m)
            total += 1
            if rep["chain"]["ok"]:
                missed += 1
            else:
                assert rep["chain"]["first_broken_seq"] is not None and rep["chain"]["first_broken_seq"] <= i
    print(f"\nplain-edit mutations: {total} tried, {missed} missed")
    assert total > 200 and missed == 0


def test_rehash_attack_on_signed_content_is_detected(scenario):
    """An attacker who edits a signed field AND recomputes every hash still fails: the signature breaks.
    Counted over every leaf of the envelope of every entry the gate allowed."""
    trail, _, _ = scenario
    bundle = trail.to_bundle()
    total = missed = 0
    for i, e in enumerate(bundle["entries"]):
        if e["gate"]["decision"] != "ALLOWED":
            continue
        for path, _ in leaves(e["envelope"]):
            m = rehash(mutate(bundle, i, ("envelope",) + path))
            rep = verify_bundle(m)
            total += 1
            detected = (not rep["chain"]["ok"]) or rep["status"] == "AUTHORITY_FINDINGS"
            if not detected:
                missed += 1
    print(f"\nrehash mutations on signed content of allowed entries: {total} tried, {missed} missed")
    assert total > 100 and missed == 0


def test_rehash_attack_on_unsigned_fields_needs_the_anchor(scenario):
    """Honest limit: the gate decision and recorded_at are not signed by any party. Rebuilding the chain
    after editing them is invisible to the verifier alone, and caught once an anchor exists."""
    trail, _, _ = scenario
    bundle = trail.to_bundle()
    seq, h = bundle["entries"][-1]["seq"], bundle["entries"][-1]["hash"]
    # an anchor made before the attack (the proof body is irrelevant for this check: the head hash is compared first)
    bundle["anchors"] = [anchor.new_ots_anchor(seq, h, ots.stamp(
        anchor.head_digest(seq, h),
        calendars=["https://cal.test"], http=fake_calendar, nonce=b"n" * 16))]
    attacked = copy.deepcopy(bundle)
    attacked["entries"][0]["recorded_at"] = "2026-01-01T00:00:00Z"  # an unsigned field
    attacked = rehash(attacked)
    rep = verify_bundle(attacked)
    assert rep["chain"]["ok"], "chain alone cannot see this"
    assert any(f["code"] == "ANCHOR_MISMATCH" for f in rep["findings"])
    assert rep["status"] == "AUTHORITY_FINDINGS"


def fake_calendar(url, data=None, headers=None, timeout=0):
    uri = url.split("/digest")[0].split("/timestamp")[0].encode()
    # pending attestation tree: tag 0x00, 8-byte tag, varbytes(varbytes(uri))
    payload = bytes([len(uri)]) + uri
    return 200, b"\x00" + ots.ATT_PENDING + bytes([len(payload)]) + payload


def test_verifier_never_crashes_on_malformed_bundles(scenario):
    """Type-confusion fuzz: replace each leaf with values of the wrong type. The verifier must always
    return a report (and must not report CLEAN), never raise."""
    trail, _, _ = scenario
    bundle = trail.to_bundle()
    weird = [None, 1.5, [1], {"a": 1}]
    runs = 0
    for i, e in enumerate(bundle["entries"]):
        for path, _ in leaves(e):
            for w in weird:
                b = copy.deepcopy(bundle)
                node = b["entries"][i]
                for p in path[:-1]:
                    node = node[p]
                node[path[-1]] = w
                rep = verify_bundle(b)
                runs += 1
                if json.dumps(b, sort_keys=True) != json.dumps(bundle, sort_keys=True):
                    assert rep["status"] != "CLEAN", (i, path, w)
    for junk in (None, 5, "x", [], {}, {"format": "authority-trail/1"}, {"format": "authority-trail/1", "entries": [1, None, "x"]},
                 {"format": "authority-trail/1", "entries": [{}]}):
        assert verify_bundle(junk)["status"] == "INTEGRITY_FAILED"
    print(f"\nfuzz runs: {runs}")
