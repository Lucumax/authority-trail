"""The independent verifier. Reads a bundle, trusts nothing in it, reports what holds.

Standard library only. It does not import the recorder: it rebuilds state from the entries.
The recorder's own ALLOWED/BLOCKED decisions are compared with the verifier's verdicts, never trusted.
"""
from __future__ import annotations

from . import anchor as anchor_mod
from .canon import digest
from .evaluate import Replay, code_of
from .keys import key_id
from .spec import FORMAT, GENESIS, parse_ts

KIND_TO_APPLY = {"grant": "apply_grant", "action": "apply_action", "revocation": "apply_revocation"}
SIG_CODES = {"BAD_SIGNATURE", "WRONG_AGENT_KEY", "GRANT_BAD_SIGNATURE", "REVOCATION_SIGNER_NOT_AUTHORISED",
             "SUBGRANT_SIGNER_NOT_PARENT_GRANTEE"}
OK_VERDICTS = ("GRANT_OK", "IN_AUTHORITY", "REVOCATION_EFFECTIVE")
STATUSES = ("CLEAN", "CLEAN_WITH_WARNINGS", "AUTHORITY_FINDINGS", "INTEGRITY_FAILED")


def _entry_hash(e: dict) -> str:
    return digest({k: v for k, v in e.items() if k != "hash"})


def _norm_pin(p: str) -> str:
    p = p.strip().lower().replace(" ", "")
    return key_id(p) if len(p) == 64 else p


def blank_report() -> dict:
    return {"entries": 0, "chain": {"ok": False, "first_broken_seq": None, "problems": []},
            "results": [], "findings": [], "anchors": [], "roots": [],
            "summary": {"grants": 0, "revocations": 0, "actions": 0, "in_authority": 0,
                        "blocked_as_expected": 0, "allowed_outside_authority": 0},
            "status": "", "unanchored_entries": 0, "verified_anchor_seq": None,
            "budget_caveat": False, "checkpoint": None, "signature_problem_seqs": []}


def verify_bundle(bundle, *, pinned_keys=None, network: bool = False, eth_rpc: str | None = None,
                  expect_head: str | None = None, require_anchor: bool = False) -> dict:
    """Return a report dict (always the same keys; see blank_report).

    pinned_keys   key ids or public keys (hex) you trust for the root grantor(s), obtained outside this file.
    network       let anchor checks query public services.
    eth_rpc       Ethereum JSON-RPC endpoint YOU choose; a bundle can never choose it.
    expect_head   'SEQ:HASH' you recorded earlier and kept apart from the log.
    require_anchor  report a HIGH finding unless an anchor is externally confirmed (implies network)."""
    try:
        return _verify_bundle(bundle, pinned_keys, network or require_anchor, eth_rpc, expect_head, require_anchor)
    except Exception as ex:  # last resort: report, do not crash
        rep = blank_report()
        rep["chain"]["problems"].append({"seq": None, "code": "VERIFIER_ERROR", "detail": type(ex).__name__})
        rep["status"] = "INTEGRITY_FAILED"
        return rep


def _verify_bundle(bundle, pinned_keys, network, eth_rpc, expect_head, require_anchor) -> dict:
    rep = blank_report()

    def finding(sev, code, seq, detail=""):
        rep["findings"].append({"severity": sev, "code": code, "seq": seq, "detail": detail})

    def chain_problem(seq, code, detail=""):
        rep["chain"]["problems"].append({"seq": seq, "code": code, "detail": detail})

    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT or not isinstance(bundle.get("entries"), list):
        chain_problem(None, "BAD_FORMAT", f"expected format {FORMAT}")
        rep["status"] = "INTEGRITY_FAILED"
        return rep
    entries = bundle["entries"]
    rep["entries"] = len(entries)

    # ---- 1. chain ----
    prev, prev_time = GENESIS, ""
    for i, e in enumerate(entries):
        try:
            if not isinstance(e, dict) or set(("seq", "prev", "recorded_at", "envelope", "hash")) - set(e):
                chain_problem(i, "ENTRY_MALFORMED")
            else:
                if not (isinstance(e["envelope"], dict) and e["envelope"].get("kind") in KIND_TO_APPLY):
                    chain_problem(i, "ENTRY_MALFORMED", "unknown record kind")
                if type(e["seq"]) is not int or e["seq"] != i:
                    chain_problem(i, "SEQ_MISMATCH", f"expected {i}")
                if e["prev"] != prev:
                    chain_problem(i, "PREV_HASH_MISMATCH")
                if _entry_hash(e) != e["hash"]:
                    chain_problem(i, "HASH_MISMATCH", "entry content does not match its hash")
                try:
                    parse_ts(e["recorded_at"])
                    if e["recorded_at"] < prev_time:
                        chain_problem(i, "TIME_REGRESSION", f"{e['recorded_at']} is before {prev_time}")
                    else:
                        prev_time = e["recorded_at"]
                except ValueError:
                    chain_problem(i, "BAD_RECORDED_AT", "not a real UTC timestamp")
        except Exception as ex:  # any shape surprise is a malformed entry, never a crash
            chain_problem(i, "ENTRY_MALFORMED", type(ex).__name__)
        prev = e.get("hash", "") if isinstance(e, dict) else ""
    probs = rep["chain"]["problems"]
    rep["chain"]["ok"] = not probs
    rep["chain"]["first_broken_seq"] = min((p["seq"] for p in probs if p["seq"] is not None), default=None)
    if probs:
        rep["status"] = "INTEGRITY_FAILED"

    # ---- 2. replay authority rules over the entries that are structurally usable ----
    rp = Replay()
    for i, e in enumerate(entries):
        try:
            usable = (isinstance(e, dict) and isinstance(e.get("envelope"), dict)
                      and e["envelope"].get("kind") in KIND_TO_APPLY and isinstance(e.get("recorded_at"), str))
            if usable:
                parse_ts(e["recorded_at"])
        except Exception:
            usable = False
        if not usable:
            continue
        env = e["envelope"]
        try:
            res = getattr(rp, KIND_TO_APPLY[env["kind"]])(env, i, e["recorded_at"])
        except Exception as ex:
            res = {"verdict": "OUT_OF_AUTHORITY" if env["kind"] == "action" else "MALFORMED",
                   "reasons": [f"RECORD_MALFORMED: {type(ex).__name__}"], "warnings": [], "id": None, "ref": None}
        gate = e.get("gate")
        gate_ok = (isinstance(gate, dict) and gate.get("decision") in ("ALLOWED", "BLOCKED")
                   and isinstance(gate.get("reasons"), list) and all(isinstance(x, str) for x in gate["reasons"]))
        if gate is None:
            decision = None
            finding("MEDIUM", "NO_GATE_RECORD", i, "entry carries no recorder decision")
        elif gate_ok:
            decision = gate["decision"]
        else:
            decision = "MALFORMED"
            finding("HIGH", "GATE_MALFORMED", i, "the recorder decision is not ALLOWED or BLOCKED with a list of reasons")
        body = env.get("body")
        r = {"seq": i, "kind": env["kind"], "id": res.get("id"), "ref": res.get("ref"), "verdict": res["verdict"],
             "reasons": res["reasons"], "warnings": res.get("warnings", []), "gate": decision,
             "recorded_at": e["recorded_at"], "body": body}
        rep["results"].append(r)
        ok_verdict = res["verdict"] in OK_VERDICTS
        sig_bad = any(code_of(x) in SIG_CODES for x in res["reasons"])
        if sig_bad:
            rep["signature_problem_seqs"].append(i)
        if not ok_verdict:
            if sig_bad and decision != "BLOCKED":
                finding("HIGH", "SIGNATURE_INVALID", i,
                        "recorded as allowed (or without a clear refusal), but the signature does not verify against "
                        "the key the grant names: the record changed after signing, or was never signed by that key")
            elif decision != "BLOCKED" and env["kind"] == "revocation":
                finding("HIGH", "REVOCATION_NOT_EFFECTIVE", i,
                        "recorded as a revocation but it has no effect, so authority the grantor withdrew may look intact: "
                        + "; ".join(res["reasons"]))
            elif decision != "BLOCKED":
                finding("HIGH", "ALLOWED_OUTSIDE_AUTHORITY", i,
                        f"recorded as allowed (or without a clear refusal) but the verifier finds {res['verdict']}: "
                        + "; ".join(res["reasons"]))
            elif sig_bad:
                finding("INFO", "REFUSED_REQUEST_NOT_AUTHENTICATED", i,
                        "a refused request whose signature does not verify; it is not a signed act of the named key")
        elif decision == "BLOCKED":
            finding("INFO", "GATE_BLOCKED_BUT_IN_AUTHORITY", i, "the recorder refused something the verifier finds valid")
        for w in res.get("warnings", []):
            finding("INFO", code_of(w), i, w)

    # post-pass: actions that claim a time after a revocation's claimed time
    for r in rep["results"]:
        if r["kind"] == "action" and r["verdict"] == "IN_AUTHORITY":
            chain, _ = rp.chain(r["body"]["grant"])
            for g in chain:
                rv = rp.revoked.get(g)
                if rv and rv["seq"] > r["seq"] and r["body"]["claimed_at"] > rv["claimed_at"]:
                    finding("MEDIUM", "ACTION_CLAIMS_TIME_AFTER_REVOCATION", r["seq"],
                            f"action claims {r['body']['claimed_at']}; revocation {rv['id']} claims {rv['claimed_at']} but was recorded later")

    # ---- 3. roots and pinned keys ----
    pins = {_norm_pin(p) for p in (pinned_keys or [])}
    for ref, g in rp.grants.items():
        b = g["body"]
        if b["parent"] is None:
            kid = key_id(b["grantor"]["key"])
            status = "NOT_CHECKED" if not pins else ("PINNED" if kid in pins else "NOT_PINNED")
            rep["roots"].append({"grant": b["id"], "ref": ref, "grantor": b["grantor"]["name"], "key_id": kid,
                                 "grantee": b["grantee"]["name"], "pinned": status, "seq": g["seq"]})
            if pins and kid not in pins:
                # a defective (for example badly signed) root grant is not a root of any authority: a stranger's
                # refused junk must not turn every pinned verification into a failure
                finding("INFO" if g["defects"] else "HIGH", "ROOT_KEY_NOT_PINNED", g["seq"],
                        f"root grantor key {kid} is not one of the keys you said to trust"
                        + (" (this root grant is defective and gives no authority)" if g["defects"] else ""))

    # ---- 4. anchors and the reader's own checkpoint ----
    for a in bundle.get("anchors", []) or []:
        rep["anchors"].append(anchor_mod.check_anchor(a, entries, network=network, eth_rpc=eth_rpc))
    for a in rep["anchors"]:
        if a["status"] in ("MISMATCH", "INVALID"):
            finding("HIGH", "ANCHOR_" + a["status"], a.get("seq"), a.get("detail", ""))
    confirmed = [a["seq"] for a in rep["anchors"] if a["status"] == "CONFIRMED" and isinstance(a.get("seq"), int)]
    rep["verified_anchor_seq"] = max(confirmed) if confirmed else None
    rep["unanchored_entries"] = (len(entries) - 1 - max(confirmed)) if confirmed else len(entries)
    if require_anchor and not confirmed:
        finding("HIGH", "ANCHOR_REQUIRED_NOT_MET", None,
                "you required an externally confirmed anchor and none was confirmed (an anchor can also simply have been removed from the file)")
    if expect_head:
        es = eh = None
        try:
            es, eh = expect_head.split(":", 1)
            es, eh = int(es), eh.strip().lower()
        except ValueError:
            es = None
            finding("HIGH", "CHECKPOINT_UNREADABLE", None, "expected head must look like SEQ:HASH")
        if es is not None:
            ok = 0 <= es < len(entries) and isinstance(entries[es], dict) and entries[es].get("hash") == eh
            rep["checkpoint"] = {"seq": es, "hash": eh, "matches": bool(ok)}
            if not ok:
                finding("HIGH", "CHECKPOINT_MISMATCH", es,
                        "the log does not contain your saved head at that position: it was shortened, rebuilt or is a different log")

    # ---- 5. summary ----
    acts = [r for r in rep["results"] if r["kind"] == "action"]
    rep["summary"] = {
        "grants": sum(1 for r in rep["results"] if r["kind"] == "grant"),
        "revocations": sum(1 for r in rep["results"] if r["kind"] == "revocation"),
        "actions": len(acts),
        "in_authority": sum(1 for r in acts if r["verdict"] == "IN_AUTHORITY"),
        "blocked_as_expected": sum(1 for r in acts if r["verdict"] == "OUT_OF_AUTHORITY" and r["gate"] == "BLOCKED"),
        "allowed_outside_authority": sum(1 for r in acts if r["verdict"] == "OUT_OF_AUTHORITY" and r["gate"] != "BLOCKED"),
    }
    if rep["summary"]["allowed_outside_authority"]:
        rep["budget_caveat"] = True
        finding("MEDIUM", "BUDGET_ACCOUNTING_CONDITIONAL", None,
                "an action recorded as allowed but outside authority may have used up a limit; in-authority verdicts "
                "that depend on those limits are conditional. Budgets count requests, not money moved")
    if not rep["status"]:
        sev = {f["severity"] for f in rep["findings"]}
        rep["status"] = "AUTHORITY_FINDINGS" if "HIGH" in sev else ("CLEAN_WITH_WARNINGS" if "MEDIUM" in sev else "CLEAN")
    return rep


def exit_code(rep: dict) -> int:
    return {"CLEAN": 0, "CLEAN_WITH_WARNINGS": 0, "INTEGRITY_FAILED": 1, "AUTHORITY_FINDINGS": 3}.get(rep["status"], 1)
