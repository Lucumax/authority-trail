"""A fictional end-to-end scenario, used by `python -m authority_trail demo` and by the tests.

All names, amounts and counterparties are invented. Keys are generated fresh and never saved.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from .keys import Party
from .spec import action_body, grant_body, make_envelope, now_ts, permission, ref_of, revocation_body
from .trail import Trail, entry_hash

AUTH_TEXT = (
    "Northgate Holdings (a fictional company) authorises its LegalOps Agent, for one week, to do three things "
    "on its behalf and nothing else. (1) Pay invoices from the outside counsel and filing firm named here, up to "
    "USD 5,000.00 per invoice and USD 12,000.00 in total. (2) Approve transfers of FUND-A units to the two listed "
    "investors named here, up to 1,000 units per transfer and 2,500 units in total. (3) Send routine notices, up to "
    "10. The agent may hand part of this authority to one more agent, never more than it holds itself. "
    "Northgate may withdraw this authority at any time by signing a revocation."
)
SUB_TEXT = "The LegalOps Agent passes to the Filing Agent only the right to send routine notices, at most 3, within the same week."


def build(clock=None, parties=None):
    """Run the scenario. Returns (trail, parties dict, outcomes list of (label, verdict))."""
    now = (clock() if clock else datetime.now(timezone.utc))
    ts = lambda d: (now + d).strftime("%Y-%m-%dT%H:%M:%SZ")
    P = parties or {
        "principal": Party("Northgate Holdings (fictional)"),
        "agent": Party("LegalOps Agent"),
        "sub": Party("Filing Agent"),
    }
    trail = Trail(clock=clock)
    out = []

    def go(label, env):
        r = trail.submit(env)["result"]
        out.append((label, r["verdict"], r["reasons"]))
        return r

    g1 = grant_body(P["principal"], P["agent"], title="Delegation to LegalOps Agent", text=AUTH_TEXT,
                    purpose="Routine legal operations and fund administration for one week",
                    not_before=ts(timedelta(minutes=-1)), expires_at=ts(timedelta(days=7)),
                    permissions=[
                        permission("pay_invoice", max_amount=500000, currency="USD", max_total=1200000,
                                   counterparties=["Harbor & Lane LLP", "Meridian Filing Services"]),
                        permission("approve_transfer", max_amount=1000, currency="FUND-A", max_total=2500,
                                   counterparties=["Investor A", "Investor B"]),
                        permission("send_notice", max_uses=10),
                    ], delegation_max_depth=1, grant_id="G-1")
    go("grant G-1 from Northgate to LegalOps Agent", make_envelope(P["principal"], "grant", g1))
    R1 = ref_of(g1)  # records refer to a grant by the hash of its body

    def act(party, grant, action, params, label, aid):
        env = make_envelope(party, "action", action_body(grant, action, params, now_ts(clock), action_id=aid))
        return go(label, env)

    pay = lambda amt, cp: {"amount": amt, "currency": "USD", "counterparty": cp}
    act(P["agent"], R1, "pay_invoice", {**pay(120000, "Harbor & Lane LLP"), "reference": "INV-1042"},
        "pay USD 1,200 to outside counsel", "A-01")
    act(P["agent"], R1, "approve_transfer", {"amount": 800, "currency": "FUND-A", "counterparty": "Investor A"},
        "approve 800 FUND-A units to a listed investor", "A-02")

    g2 = grant_body(P["agent"], P["sub"], title="Sub-delegation to Filing Agent", text=SUB_TEXT,
                    purpose="Send routine notices only", not_before=ts(timedelta(minutes=0)),
                    expires_at=ts(timedelta(days=3)), permissions=[permission("send_notice", max_uses=3)],
                    parent=R1, grant_id="G-2")
    go("sub-grant G-2 from LegalOps Agent to Filing Agent", make_envelope(P["agent"], "grant", g2))
    R2 = ref_of(g2)
    act(P["sub"], R2, "send_notice", {"notice": "Annual filing reminder"}, "Filing Agent sends a notice", "A-03")

    act(P["agent"], R1, "pay_invoice", pay(900000, "Harbor & Lane LLP"),
        "attempt USD 9,000 (over the per-invoice limit)", "A-04")
    act(P["agent"], R1, "approve_transfer", {"amount": 500, "currency": "FUND-A", "counterparty": "Unlisted Fund LP"},
        "attempt transfer to a counterparty not on the list", "A-05")
    act(P["sub"], R2, "pay_invoice", pay(1000, "Harbor & Lane LLP"),
        "Filing Agent attempts a payment (not delegated)", "A-06")
    act(P["agent"], R1, "pay_invoice", pay(450000, "Meridian Filing Services"), "pay USD 4,500 to filing firm", "A-07")
    act(P["agent"], R1, "pay_invoice", pay(450000, "Meridian Filing Services"), "pay USD 4,500 to filing firm again", "A-08")
    act(P["agent"], R1, "pay_invoice", pay(300000, "Harbor & Lane LLP"),
        "attempt USD 3,000 (would pass USD 12,000 in total)", "A-09")

    go("Northgate revokes G-1", make_envelope(P["principal"], "revocation",
        revocation_body(R1, "Engagement paused pending board review", now_ts(clock), rev_id="R-1")))
    act(P["agent"], R1, "pay_invoice", pay(50000, "Harbor & Lane LLP"), "attempt a payment after revocation", "A-10")
    act(P["sub"], R2, "send_notice", {"notice": "Second reminder"}, "Filing Agent tries after its parent grant was revoked", "A-11")
    return trail, P, out


def rogue_variant(trail: Trail, P: dict) -> Trail:
    """Copy of the log with a dishonest operator who force-records an over-limit payment as ALLOWED
    (the attempt was signed by the real agent, so the signature is genuine; the gate decision is a lie)."""
    t2 = copy.deepcopy(trail)
    env = make_envelope(P["agent"], "action", action_body(
        ref_of(t2.entries[0]["envelope"]["body"]), "pay_invoice", {"amount": 9900000, "currency": "USD", "counterparty": "Harbor & Lane LLP"},
        t2.entries[-1]["recorded_at"], action_id="A-99"))
    t2.submit(env, _gate_override="ALLOWED")
    return t2


# ----- tamper helpers (operate on a bundle dict, return a modified copy) -----

def tamper_amount(bundle: dict, new_amount: int = 120) -> dict:
    """Edit one recorded payment amount in place. The hash is NOT recomputed: a plain edit."""
    b = copy.deepcopy(bundle)
    for e in b["entries"]:
        env = e["envelope"]
        if env["kind"] == "action" and env["body"]["action"] == "pay_invoice" and e["gate"]["decision"] == "ALLOWED":
            env["body"]["params"]["amount"] = new_amount
            return b
    raise ValueError("no allowed payment found")


def tamper_rehash(bundle: dict, new_amount: int = 120) -> dict:
    """A careful attacker: edit the amount AND recompute every hash after it so the chain looks intact.
    The edited envelope's signature no longer verifies, and an anchor made earlier no longer matches."""
    b = tamper_amount(bundle, new_amount)
    prev = "0" * 64
    for e in b["entries"]:
        e["prev"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    return b
