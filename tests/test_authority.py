import copy
import json

import pytest

from authority_trail import demo, ed25519, memo
from authority_trail.keys import Party, key_id
from authority_trail.spec import (action_body, grant_body, make_envelope, permission, ref_of, revocation_body)
from authority_trail.trail import Trail, TrailError, entry_hash
from authority_trail.verify import exit_code, verify_bundle


def codes(res):
    return {r.split(":", 1)[0] for r in res["reasons"]}


def mk(clock, perms, parent=None, depth=0, nb=-10, ex=3600, grantor=None, grantee=None, gid="G-1"):
    """Build a signed grant envelope. Returns (grantor, grantee, envelope, ref)."""
    gr, ge = grantor or Party("P"), grantee or Party("A")
    t = clock.iso
    body = grant_body(gr, ge, title="t", text="the wording", purpose="p", not_before=t(seconds=nb),
                      expires_at=t(seconds=ex), permissions=perms, parent=parent,
                      delegation_max_depth=depth, grant_id=gid)
    return gr, ge, make_envelope(gr, "grant", body), ref_of(body)


def act(clock, who, ref, action, params, aid):
    return make_envelope(who, "action", action_body(ref, action, params, clock.iso(), action_id=aid))


def sub_grant(clock, parent_ref, grantor, grantee, perms, gid, depth=0, nb=-5, ex=500):
    return make_envelope(grantor, "grant", grant_body(grantor, grantee, title="t", text="w", purpose="p",
                                                      not_before=clock.iso(seconds=nb), expires_at=clock.iso(seconds=ex),
                                                      permissions=perms, parent=parent_ref, grant_id=gid,
                                                      delegation_max_depth=depth))


def rebuild_chain(bundle):
    prev = "0" * 64
    for e in bundle["entries"]:
        e["prev"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    return bundle


# ---------------------------------------------------------------- the scenario

def test_demo_scenario_outcomes(scenario):
    trail, P, outcomes = scenario
    verdicts = [v for _, v, _ in outcomes]
    assert verdicts.count("IN_AUTHORITY") == 5
    assert verdicts.count("OUT_OF_AUTHORITY") == 6
    reasons = {label: {r.split(":")[0] for r in rs} for label, _, rs in outcomes}
    assert "AMOUNT_OVER_LIMIT" in reasons["attempt USD 9,000 (over the per-invoice limit)"]
    assert "COUNTERPARTY_NOT_ALLOWED" in reasons["attempt transfer to a counterparty not on the list"]
    assert "ACTION_NOT_PERMITTED" in reasons["Filing Agent attempts a payment (not delegated)"]
    assert "CUMULATIVE_LIMIT_EXCEEDED" in reasons["attempt USD 3,000 (would pass USD 12,000 in total)"]
    assert "GRANT_REVOKED" in reasons["attempt a payment after revocation"]
    assert "GRANT_REVOKED" in reasons["Filing Agent tries after its parent grant was revoked"]


def test_verifier_agrees_with_recorder_and_is_clean(scenario):
    trail, P, _ = scenario
    rep = verify_bundle(trail.to_bundle(), pinned_keys=[P["principal"].key_id])
    assert rep["status"] in ("CLEAN", "CLEAN_WITH_WARNINGS") and exit_code(rep) == 0
    assert rep["chain"]["ok"] and rep["summary"]["in_authority"] == 5 and rep["summary"]["blocked_as_expected"] == 6
    assert rep["roots"][0]["pinned"] == "PINNED"
    for e, r in zip(trail.entries, rep["results"]):
        ok = r["verdict"] in ("GRANT_OK", "IN_AUTHORITY", "REVOCATION_EFFECTIVE")
        assert (e["gate"]["decision"] == "ALLOWED") == ok


def test_wrong_pin_is_a_high_finding(scenario):
    trail, _, _ = scenario
    rep = verify_bundle(trail.to_bundle(), pinned_keys=["0" * 32])
    assert rep["status"] == "AUTHORITY_FINDINGS"
    assert any(f["code"] == "ROOT_KEY_NOT_PINNED" for f in rep["findings"])


def test_rogue_operator_forced_allow_is_caught(scenario):
    trail, P, _ = scenario
    rogue = demo.rogue_variant(trail, P)
    rep = verify_bundle(rogue.to_bundle())
    assert rep["status"] == "AUTHORITY_FINDINGS" and exit_code(rep) == 3
    assert rep["chain"]["ok"]
    assert any(f["code"] == "ALLOWED_OUTSIDE_AUTHORITY" for f in rep["findings"])
    assert rep["summary"]["allowed_outside_authority"] == 1
    assert rep["budget_caveat"] and any(f["code"] == "BUDGET_ACCOUNTING_CONDITIONAL" for f in rep["findings"])


# ---------------------------------------------------------------- windows and keys

def test_window_edges(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], nb=5, ex=10)
    t.submit(g)
    assert "GRANT_NOT_YET_VALID" in codes(t.submit(act(clock, ge, ref, "send_notice", {}, "A-1"))["result"])
    for _ in range(12):
        clock()
    assert "GRANT_EXPIRED" in codes(t.submit(act(clock, ge, ref, "send_notice", {}, "A-2"))["result"])


def test_claimed_time_outside_window_fails_even_if_recorded_time_is_inside(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], nb=-100, ex=100)
    t.submit(g)
    env = make_envelope(ge, "action", action_body(ref, "send_notice", {}, clock.iso(seconds=-5000), action_id="A-1"))
    assert "GRANT_NOT_YET_VALID" in codes(t.submit(env)["result"])
    env = make_envelope(ge, "action", action_body(ref, "send_notice", {}, clock.iso(seconds=5000), action_id="A-2"))
    assert "GRANT_EXPIRED" in codes(t.submit(env)["result"])


def test_wrong_signer_and_forged_signature(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    assert "WRONG_AGENT_KEY" in codes(t.submit(act(clock, Party("S"), ref, "send_notice", {}, "A-1"))["result"])
    env = act(clock, ge, ref, "send_notice", {}, "A-2")
    env["body"]["params"] = {"extra": 1}  # changed after signing
    assert "BAD_SIGNATURE" in codes(t.submit(env)["result"])


def test_forged_grant_not_signed_by_named_grantor(clock):
    t = Trail(clock)
    gr, ge = Party("P"), Party("A")
    body = grant_body(gr, ge, title="t", text="x", purpose="p", not_before=clock.iso(seconds=-5),
                      expires_at=clock.iso(seconds=500), permissions=[permission("send_notice")], grant_id="G-1")
    r = t.submit(make_envelope(Party("Mallory"), "grant", body))["result"]
    assert r["verdict"] == "GRANT_DEFECTIVE" and "GRANT_BAD_SIGNATURE" in codes(r)
    assert "UNKNOWN_GRANT" in codes(t.submit(act(clock, ge, ref_of(body), "send_notice", {}, "A-1"))["result"])  # never stored


def test_instrument_text_is_bound_by_hash(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    g["body"]["instrument"]["text"] = "different words"
    g = make_envelope(gr, "grant", g["body"])  # re-signed, but the hash no longer matches the text
    assert "INSTRUMENT_HASH_MISMATCH" in codes(t.submit(g)["result"])


def test_small_order_keys_are_refused(clock):
    """A grant naming the identity point as the agent key would let anyone 'sign' as the agent."""
    identity = b"\x01" + b"\x00" * 31
    assert ed25519.verify(identity, b"m", identity + b"\x00" * 32) is False
    assert not ed25519.is_valid_public(identity)
    t = Trail(clock)
    gr, ge = Party("P"), Party("A")
    body = grant_body(gr, ge, title="t", text="w", purpose="p", not_before=clock.iso(seconds=-5),
                      expires_at=clock.iso(seconds=500), permissions=[permission("pay", max_amount=100, currency="USD")],
                      grant_id="G-1")
    body["grantee"]["key"] = identity.hex()
    r = t.submit(make_envelope(gr, "grant", body))["result"]
    assert r["verdict"] == "GRANT_DEFECTIVE" and "GRANT_BAD_GRANTEE" in codes(r)
    forged = {"kind": "action", "signer": key_id(identity.hex()), "sig": (identity + b"\x00" * 32).hex(),
              "body": action_body(ref_of(body), "pay", {"amount": 100, "currency": "USD"}, clock.iso(), action_id="F")}
    assert t.submit(forged)["result"]["verdict"] == "OUT_OF_AUTHORITY"


def test_all_eight_small_order_points_are_rejected():
    small = ["0000000000000000000000000000000000000000000000000000000000000000",
             "0000000000000000000000000000000000000000000000000000000000000080",
             "0100000000000000000000000000000000000000000000000000000000000000",
             "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
             "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
             "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
             "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
             "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"]
    for h in small:
        assert not ed25519.is_valid_public(bytes.fromhex(h)), h


# ---------------------------------------------------------------- limits

def test_missing_amount_and_currency_fail_closed(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", max_amount=100, currency="USD", counterparties=["X"])])
    t.submit(g)
    ok = {"currency": "USD", "counterparty": "X"}
    assert "AMOUNT_MISSING_OR_INVALID" in codes(t.submit(act(clock, ge, ref, "pay", {"counterparty": "X", "currency": "USD"}, "A-1"))["result"])
    assert "CURRENCY_MISMATCH" in codes(t.submit(act(clock, ge, ref, "pay", {"amount": 5, "currency": "EUR", "counterparty": "X"}, "A-3"))["result"])
    assert "COUNTERPARTY_NOT_ALLOWED" in codes(t.submit(act(clock, ge, ref, "pay", {"amount": 5, "currency": "USD"}, "A-4"))["result"])
    assert t.submit(act(clock, ge, ref, "pay", {"amount": 100, **ok}, "A-5"))["result"]["verdict"] == "IN_AUTHORITY"
    assert "AMOUNT_OVER_LIMIT" in codes(t.submit(act(clock, ge, ref, "pay", {"amount": 101, **ok}, "A-6"))["result"])
    assert "AMOUNT_MISSING_OR_INVALID" in codes(t.submit(act(clock, ge, ref, "pay", {"amount": True, **ok}, "A-7"))["result"])
    assert "AMOUNT_MISSING_OR_INVALID" in codes(t.submit(act(clock, ge, ref, "pay", {"amount": -1, **ok}, "A-8"))["result"])


def test_currency_must_match_even_when_amount_is_unusable(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", currency="USD", counterparties=["X"])])
    t.submit(g)
    for i, params in enumerate(({"amount": "lots", "counterparty": "X"},
                                {"amount": True, "currency": "EUR", "counterparty": "X"},
                                {"counterparty": "X"})):
        assert "CURRENCY_MISMATCH" in codes(t.submit(act(clock, ge, ref, "pay", params, f"A-{i}"))["result"])


def test_amount_limit_without_currency_is_a_defective_grant(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", max_amount=100)])
    r = t.submit(g)["result"]
    assert r["verdict"] == "GRANT_DEFECTIVE" and "PERMISSION_AMOUNT_WITHOUT_CURRENCY" in codes(r)


def test_max_uses_and_identical_replay(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice", max_uses=2)])
    t.submit(g)
    env = act(clock, ge, ref, "send_notice", {}, "A-1")
    assert t.submit(env)["result"]["verdict"] == "IN_AUTHORITY"
    assert "ACTION_REPLAYED" in codes(t.submit(env)["result"])  # the same signed record again
    assert t.submit(act(clock, ge, ref, "send_notice", {}, "A-2"))["result"]["verdict"] == "IN_AUTHORITY"
    assert "USES_EXCEEDED" in codes(t.submit(act(clock, ge, ref, "send_notice", {}, "A-3"))["result"])


# ---------------------------------------------------------------- identifiers cannot be squatted

def test_label_squatting_cannot_block_or_replace_a_genuine_grant(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    mal = Party("Mallory")
    _, _, fake, fake_ref = mk(clock, [permission("send_notice")], grantor=mal, grantee=mal, gid="G-1")  # same label
    t.submit(fake)
    assert t.submit(g)["result"]["verdict"] == "GRANT_OK"
    assert ref != fake_ref
    assert t.submit(act(clock, ge, ref, "send_notice", {}, "A-1"))["result"]["verdict"] == "IN_AUTHORITY"


def test_unauthorised_revocation_does_not_reserve_anything(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    t.submit(make_envelope(Party("Mallory"), "revocation", revocation_body(ref, "x", clock.iso(), rev_id="R-1")))
    ok = t.submit(make_envelope(gr, "revocation", revocation_body(ref, "real", clock.iso(), rev_id="R-1")))["result"]
    assert ok["verdict"] == "REVOCATION_EFFECTIVE"
    assert "GRANT_REVOKED" in codes(t.submit(act(clock, ge, ref, "send_notice", {}, "A-1"))["result"])


def test_action_label_squatting_does_not_block_the_genuine_action(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    t.submit(act(clock, Party("Mallory"), ref, "send_notice", {}, "A-1"))  # refused, same label
    assert t.submit(act(clock, ge, ref, "send_notice", {}, "A-1"))["result"]["verdict"] == "IN_AUTHORITY"


# ---------------------------------------------------------------- delegation

def test_subgrant_must_narrow_in_every_respect(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", max_amount=100, currency="USD", counterparties=["X", "Y"], max_total=300)], depth=1)
    t.submit(g)
    sub = Party("Sub")

    def P(**kw):
        return [permission("pay", **{"max_amount": 50, "currency": "USD", "counterparties": ["X"], "max_total": 100, **kw})]

    def result(perms, gid, **kw):
        return t.submit(sub_grant(clock, ref, ge, sub, perms, gid, **kw))["result"]

    assert "SCOPE_AMOUNT_WIDER" in codes(result(P(max_amount=200), "S1"))
    assert "SCOPE_COUNTERPARTIES_WIDER" in codes(result(P(counterparties=["Z"]), "S2"))
    assert "SCOPE_TOTAL_WIDER" in codes(result([permission("pay", max_amount=50, currency="USD", counterparties=["X"])], "S3"))
    assert "SCOPE_COUNTERPARTIES_WIDER" in codes(result([permission("pay", max_amount=50, currency="USD", max_total=100)], "S3b"))
    assert "SCOPE_ACTION_NOT_IN_PARENT" in codes(result([permission("sign")], "S4"))
    assert "DELEGATION_DEPTH_EXCEEDED" in codes(result(P(), "S5", depth=1))
    assert "SCOPE_OUTLIVES_PARENT" in codes(result(P(), "S5b", ex=99999))
    assert "SCOPE_STARTS_BEFORE_PARENT" in codes(result(P(), "S5c", nb=-9999))
    assert result(P(), "S6")["verdict"] == "GRANT_OK"


def test_subgrant_may_not_drop_the_currency_condition(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", currency="USD", counterparties=["X"])], depth=1)
    t.submit(g)
    sub = Party("Sub")
    r = t.submit(sub_grant(clock, ref, ge, sub, [permission("pay", counterparties=["X"])], "S1"))["result"]
    assert "SCOPE_CURRENCY_NOT_KEPT" in codes(r)
    r = t.submit(sub_grant(clock, ref, ge, sub, [permission("pay", currency="EUR", counterparties=["X"])], "S2"))["result"]
    assert "SCOPE_CURRENCY_NOT_KEPT" in codes(r)


def test_delegation_not_allowed(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], depth=0)
    t.submit(g)
    r = t.submit(sub_grant(clock, ref, ge, Party("Sub"), [permission("send_notice")], "S1"))["result"]
    assert "DELEGATION_NOT_ALLOWED" in codes(r)


def test_subgrant_signed_by_the_wrong_party_or_with_unknown_parent(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], depth=1)
    t.submit(g)
    sub, mal = Party("Sub"), Party("Mal")
    assert "SUBGRANT_SIGNER_NOT_PARENT_GRANTEE" in codes(t.submit(sub_grant(clock, ref, mal, sub, [permission("send_notice")], "S"))["result"])
    assert "PARENT_UNKNOWN" in codes(t.submit(sub_grant(clock, "ab" * 32, ge, sub, [permission("send_notice")], "S2"))["result"])


def test_subgrant_after_parent_revoked(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], depth=1)
    t.submit(g)
    t.submit(make_envelope(gr, "revocation", revocation_body(ref, "stop", clock.iso(), rev_id="R")))
    r = t.submit(sub_grant(clock, ref, ge, Party("Sub"), [permission("send_notice")], "S"))["result"]
    assert "PARENT_REVOKED" in codes(r)


def test_budgets_are_shared_up_the_chain(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", max_amount=100, currency="USD", max_total=150)], depth=1)
    t.submit(g)
    sub = Party("Sub")
    sg = sub_grant(clock, ref, ge, sub, [permission("pay", max_amount=100, currency="USD", max_total=150)], "S")
    assert t.submit(sg)["result"]["verdict"] == "GRANT_OK"
    sref = ref_of(sg["body"])
    assert t.submit(act(clock, ge, ref, "pay", {"amount": 100, "currency": "USD"}, "A-1"))["result"]["verdict"] == "IN_AUTHORITY"
    r = t.submit(act(clock, sub, sref, "pay", {"amount": 100, "currency": "USD"}, "A-2"))["result"]
    assert "CUMULATIVE_LIMIT_EXCEEDED" in codes(r)


def test_revocation_rights(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")], depth=1)
    t.submit(g)
    sub = Party("Sub")
    sg = sub_grant(clock, ref, ge, sub, [permission("send_notice")], "S")
    t.submit(sg)
    sref = ref_of(sg["body"])
    bad = t.submit(make_envelope(ge, "revocation", revocation_body(ref, "agent revokes own parent", clock.iso(), rev_id="R0")))["result"]
    assert bad["verdict"] == "REVOCATION_INEFFECTIVE" and "REVOCATION_SIGNER_NOT_AUTHORISED" in codes(bad)
    assert t.submit(act(clock, sub, sref, "send_notice", {}, "A-1"))["result"]["verdict"] == "IN_AUTHORITY"
    unknown = t.submit(make_envelope(gr, "revocation", revocation_body("cd" * 32, "x", clock.iso(), rev_id="R1")))["result"]
    assert "REVOCATION_UNKNOWN_GRANT" in codes(unknown)
    ok = t.submit(make_envelope(ge, "revocation", revocation_body(sref, "withdrawn", clock.iso(), rev_id="R2")))["result"]
    assert ok["verdict"] == "REVOCATION_EFFECTIVE"  # the agent may withdraw the sub-grant it issued
    assert "GRANT_REVOKED" in codes(t.submit(act(clock, sub, sref, "send_notice", {}, "A-2"))["result"])
    assert t.submit(act(clock, ge, ref, "send_notice", {}, "A-3"))["result"]["verdict"] == "IN_AUTHORITY"  # parent unaffected
    sg2 = sub_grant(clock, ref, ge, sub, [permission("send_notice")], "S-other")
    t.submit(sg2)
    top = t.submit(make_envelope(gr, "revocation", revocation_body(ref_of(sg2["body"]), "by ancestor", clock.iso(), rev_id="R3")))["result"]
    assert top["verdict"] == "REVOCATION_EFFECTIVE"  # the root grantor may withdraw a descendant


def test_recorded_order_beats_claimed_time(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    early = clock.iso()
    t.submit(make_envelope(gr, "revocation", revocation_body(ref, "stop", clock.iso())))
    env = make_envelope(ge, "action", action_body(ref, "send_notice", {}, early, action_id="A-1"))
    assert "GRANT_REVOKED" in codes(t.submit(env)["result"])


# ---------------------------------------------------------------- recorder state and persistence

def test_caller_cannot_change_authority_after_signing(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", max_amount=1, currency="USD")])
    t.submit(g)
    g["body"]["permissions"][0]["max_amount"] = 100  # mutate the caller's copy
    r = t.submit(act(clock, ge, ref, "pay", {"amount": 50, "currency": "USD"}, "A-1"))
    assert "AMOUNT_OVER_LIMIT" in codes(r["result"])
    r["entry"]["envelope"]["body"]["id"] = "tampered"  # mutate what submit returned
    assert t.entries[-1]["envelope"]["body"]["id"] == "A-1"
    b = t.to_bundle()
    b["entries"][0]["recorded_at"] = "x"
    assert t.entries[0]["recorded_at"] != "x"


def test_unhashable_record_is_refused_before_any_state_changes(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    env = act(clock, ge, ref, "send_notice", {}, "A-1")
    env["body"]["params"] = {"n": 1.5}
    n = len(t.entries)
    with pytest.raises(TrailError):
        t.submit(env)
    assert len(t.entries) == n and not t.replay.action_refs


def test_persistence_roundtrip_and_load_refuses_broken_log(scenario, tmp_path):
    trail, _, _ = scenario
    p = tmp_path / "t.json"
    trail.save(str(p))
    again = Trail.load(str(p))
    assert again.head() == trail.head()
    b = json.loads(p.read_text(encoding="utf-8"))
    b["entries"][1]["envelope"]["body"]["params"]["amount"] = 1
    p.write_text(json.dumps(b), encoding="utf-8")
    with pytest.raises(TrailError):
        Trail.load(str(p))


# ---------------------------------------------------------------- verifier strictness

def test_gate_field_is_validated_not_trusted(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("pay", max_amount=10, currency="USD")])
    t.submit(g)
    t.submit(act(clock, ge, ref, "pay", {"amount": 11, "currency": "USD"}, "A-1"))  # refused
    b = t.to_bundle()
    b["entries"][-1]["gate"]["decision"] = "ALLOW"  # not a legal value
    rep = verify_bundle(rebuild_chain(b))
    assert rep["status"] == "AUTHORITY_FINDINGS"
    assert {"GATE_MALFORMED", "ALLOWED_OUTSIDE_AUTHORITY"} <= {f["code"] for f in rep["findings"]}


def test_refused_request_with_bad_signature_is_reported(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    t.submit(act(clock, Party("Impostor"), ref, "send_notice", {}, "A-1"))
    rep = verify_bundle(t.to_bundle())
    assert rep["status"] == "CLEAN"
    assert any(f["code"] == "REFUSED_REQUEST_NOT_AUTHENTICATED" for f in rep["findings"])


def test_boolean_seq_and_impossible_time_fail_the_chain(clock):
    t = Trail(clock)
    gr, ge, g, ref = mk(clock, [permission("send_notice")])
    t.submit(g)
    t.submit(act(clock, ge, ref, "send_notice", {}, "A-1"))
    for mutate in (lambda e: e.__setitem__("seq", True), lambda e: e.__setitem__("recorded_at", "2026-10-27T12:00:60Z")):
        b = t.to_bundle()
        mutate(b["entries"][1])
        assert verify_bundle(rebuild_chain(b))["status"] == "INTEGRITY_FAILED"


def test_checkpoint_and_required_anchor(scenario):
    trail, _, _ = scenario
    b = trail.to_bundle()
    head = f"{b['entries'][-1]['seq']}:{b['entries'][-1]['hash']}"
    assert verify_bundle(b, expect_head=head)["checkpoint"]["matches"] is True
    short = copy.deepcopy(b)
    short["entries"] = short["entries"][:-2]
    rep = verify_bundle(short, expect_head=head)
    assert any(f["code"] == "CHECKPOINT_MISMATCH" for f in rep["findings"])
    assert any(f["code"] == "CHECKPOINT_UNREADABLE" for f in verify_bundle(b, expect_head="garbage")["findings"])
    rep = verify_bundle(b, require_anchor=True)
    assert any(f["code"] == "ANCHOR_REQUIRED_NOT_MET" for f in rep["findings"]) and rep["status"] == "AUTHORITY_FINDINGS"


def test_rebuilt_shorter_log_is_caught_by_a_saved_head(scenario):
    """The anchor can be deleted from a bundle; a head the reader saved elsewhere cannot."""
    trail, _, _ = scenario
    b = trail.to_bundle()
    head = f"{b['entries'][-1]['seq']}:{b['entries'][-1]['hash']}"
    b["entries"][2]["recorded_at"] = "2026-01-01T00:00:00Z"  # unsigned field
    b["entries"] = rebuild_chain(b)["entries"]
    b["anchors"] = []
    rep = verify_bundle(b, expect_head=head)
    assert any(f["code"] == "CHECKPOINT_MISMATCH" for f in rep["findings"])


def test_memo_prints_the_wording_and_survives_failed_reports(scenario):
    trail, P, _ = scenario
    rep = verify_bundle(trail.to_bundle(), pinned_keys=[P["principal"].key_id])
    text = memo.render(rep, trail.to_bundle())
    flat = " ".join(line.replace("|", " ") for line in text.split("\n"))
    assert " ".join(demo.AUTH_TEXT.split()[:12]) in " ".join(flat.split())  # the operative wording is printed in full
    assert "SHA-256 of that wording:" in text and "compare them with the wording" in text
    assert "recorder reported" in text and "does not establish" in text
    for junk in (None, 5, [], {"format": "authority-trail/1", "entries": [1]}):
        assert "INTEGRITY_FAILED" in memo.render(verify_bundle(junk), junk)
