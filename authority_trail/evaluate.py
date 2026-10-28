"""The authority rules. One implementation used by the recorder (to gate) and the verifier (to re-check).

Replay processes log entries in order. Order in the log decides what was in force:
an action recorded after a revocation entry is outside authority, whatever time it claims.

Records refer to each other by content hash (spec.ref_of), never by label, so an attacker cannot
squat a label or make a genuine record look like a duplicate. Labels (`id`) are for display.

Budgets (max_uses, max_total) count REQUESTS judged in authority. They are not a ledger of money
moved: nothing here sees whether a payment happened. See docs/DESIGN.md.
"""
from __future__ import annotations

from .keys import key_id
from .spec import (envelope_signature_ok, parse_ts, ref_of, validate_action_body, validate_grant_body,
                   validate_revocation_body)

SKEW_WARN_SECONDS = 300


def _r(code: str, detail: str = "") -> str:
    return f"{code}: {detail}" if detail else code


def code_of(reason: str) -> str:
    return reason.split(":", 1)[0]


def _find_perm(body: dict, action: str):
    for p in body["permissions"]:
        if p["action"] == action:
            return p
    return None


def scope_subset_problems(child: dict, parent: dict) -> list[str]:
    """Why `child` grant body is not a narrowing of `parent` grant body (empty list = it is).
    Every condition the parent states must be stated again, at least as tight, by the child."""
    out = []
    if child["not_before"] < parent["not_before"]:
        out.append(_r("SCOPE_STARTS_BEFORE_PARENT"))
    if child["expires_at"] > parent["expires_at"]:
        out.append(_r("SCOPE_OUTLIVES_PARENT"))
    for c in child["permissions"]:
        p = _find_perm(parent, c["action"])
        if p is None:
            out.append(_r("SCOPE_ACTION_NOT_IN_PARENT", c["action"]))
            continue
        if "currency" in p and c.get("currency") != p["currency"]:
            out.append(_r("SCOPE_CURRENCY_NOT_KEPT", c["action"]))
        if "max_amount" in p and not ("max_amount" in c and c["max_amount"] <= p["max_amount"]):
            out.append(_r("SCOPE_AMOUNT_WIDER", c["action"]))
        if "max_total" in p and not ("max_total" in c and c["max_total"] <= p["max_total"]):
            out.append(_r("SCOPE_TOTAL_WIDER", c["action"]))
        if "max_uses" in p and not ("max_uses" in c and c["max_uses"] <= p["max_uses"]):
            out.append(_r("SCOPE_USES_WIDER", c["action"]))
        if "counterparties" in p and not ("counterparties" in c
                                          and set(c["counterparties"]) <= set(p["counterparties"])):
            out.append(_r("SCOPE_COUNTERPARTIES_WIDER", c["action"]))
    return out


def _label(g: dict, ref: str) -> str:
    return f"{g['body'].get('id', '?')} [{ref[:8]}]"


class Replay:
    def __init__(self) -> None:
        self.grants: dict[str, dict] = {}     # ref -> {body, seq, recorded_at, defects}
        self.revoked: dict[str, dict] = {}    # grant ref -> {seq, claimed_at, id}
        self.usage: dict[tuple, list] = {}    # (grant ref, action) -> [uses, total]
        self.action_refs: set[str] = set()
        self.revocation_refs: set[str] = set()

    # ----- helpers -----
    def chain(self, ref: str):
        """Grant refs from the given grant up to the root, and the ref of a missing parent if any."""
        out, seen, cur = [], set(), ref
        while cur is not None:
            if cur in seen:
                return out, cur
            g = self.grants.get(cur)
            if g is None:
                return out, cur
            seen.add(cur)
            out.append(cur)
            cur = g["body"]["parent"]
        return out, None

    def revoked_in_chain(self, ref: str, before_seq: int):
        chain, _ = self.chain(ref)
        return [g for g in chain if g in self.revoked and self.revoked[g]["seq"] < before_seq]

    # ----- grants -----
    def apply_grant(self, env: dict, seq: int, recorded_at: str) -> dict:
        body = env.get("body")
        reasons = validate_grant_body(body)
        if reasons:
            return {"verdict": "GRANT_DEFECTIVE", "reasons": reasons, "id": _safe_id(body), "ref": None}
        ref = ref_of(body)
        gkey = body["grantor"]["key"]
        if not envelope_signature_ok(env, gkey):
            # A copy of a grant body that is not signed by the named grantor is not a grant. It is not stored,
            # so it cannot occupy the ref that the genuine, correctly signed record needs.
            return {"verdict": "GRANT_DEFECTIVE",
                    "reasons": [_r("GRANT_BAD_SIGNATURE", "not signed by the named grantor key")],
                    "id": body["id"], "ref": ref}
        existing = self.grants.get(ref)
        if existing is not None and not existing["defects"]:
            return {"verdict": "GRANT_DEFECTIVE", "reasons": [_r("GRANT_ALREADY_RECORDED", ref[:8])],
                    "id": body["id"], "ref": ref}
        parent_ref = body["parent"]
        if parent_ref is not None:
            par = self.grants.get(parent_ref)
            if par is None:
                reasons.append(_r("PARENT_UNKNOWN", parent_ref[:8]))
            else:
                pb = par["body"]
                if par["defects"]:
                    reasons.append(_r("PARENT_DEFECTIVE", _label(par, parent_ref)))
                if gkey != pb["grantee"]["key"]:
                    reasons.append(_r("SUBGRANT_SIGNER_NOT_PARENT_GRANTEE", _label(par, parent_ref)))
                if not pb["delegation"]["allowed"]:
                    reasons.append(_r("DELEGATION_NOT_ALLOWED", _label(par, parent_ref)))
                elif body["delegation"]["max_depth"] > pb["delegation"]["max_depth"] - 1:
                    reasons.append(_r("DELEGATION_DEPTH_EXCEEDED", _label(par, parent_ref)))
                if self.revoked_in_chain(parent_ref, seq):
                    reasons.append(_r("PARENT_REVOKED", _label(par, parent_ref)))
                if not (pb["not_before"] <= recorded_at < pb["expires_at"]):
                    reasons.append(_r("PARENT_NOT_IN_FORCE", _label(par, parent_ref)))
                reasons.extend(scope_subset_problems(body, pb))
        if existing is not None and reasons:
            # an earlier copy was defective (for example recorded before its parent) and this one is no better
            return {"verdict": "GRANT_DEFECTIVE", "reasons": reasons + [_r("GRANT_ALREADY_RECORDED", ref[:8])],
                    "id": body["id"], "ref": ref}
        # a first copy, or a sound copy that replaces an earlier defective one
        self.grants[ref] = {"body": body, "seq": seq, "recorded_at": recorded_at, "defects": list(reasons)}
        return {"verdict": "GRANT_DEFECTIVE" if reasons else "GRANT_OK", "reasons": reasons,
                "id": body["id"], "ref": ref}

    # ----- revocations -----
    def apply_revocation(self, env: dict, seq: int, recorded_at: str) -> dict:
        body = env.get("body")
        errs = validate_revocation_body(body)
        if errs:
            return {"verdict": "REVOCATION_INEFFECTIVE", "reasons": errs, "id": _safe_id(body), "ref": None}
        rref, target = ref_of(body), body["grant"]
        out = {"verdict": "REVOCATION_INEFFECTIVE", "id": body["id"], "ref": rref}
        if target not in self.grants:
            return {**out, "reasons": [_r("REVOCATION_UNKNOWN_GRANT", target[:8])]}
        chain, _ = self.chain(target)
        allowed_keys = [self.grants[g]["body"]["grantor"]["key"] for g in chain]
        if not any(envelope_signature_ok(env, k) for k in allowed_keys):
            return {**out, "reasons": [_r("REVOCATION_SIGNER_NOT_AUTHORISED",
                                          "must be signed by the grantor of the grant or of an ancestor")]}
        if rref in self.revocation_refs:
            return {**out, "reasons": [_r("REVOCATION_ALREADY_RECORDED", rref[:8])]}
        self.revocation_refs.add(rref)
        if target not in self.revoked:
            self.revoked[target] = {"seq": seq, "claimed_at": body["claimed_at"], "id": body["id"]}
        return {**out, "verdict": "REVOCATION_EFFECTIVE", "reasons": []}

    # ----- actions -----
    def evaluate_action(self, env: dict, seq: int, recorded_at: str) -> dict:
        body = env.get("body")
        errs = validate_action_body(body)
        if errs:
            return {"verdict": "OUT_OF_AUTHORITY", "reasons": [_r("ACTION_MALFORMED", ",".join(errs))],
                    "warnings": [], "id": _safe_id(body), "ref": None}
        reasons: list[str] = []
        warnings: list[str] = []
        aref, gref = ref_of(body), body["grant"]
        res = {"id": body["id"], "ref": aref}
        if aref in self.action_refs:
            reasons.append(_r("ACTION_REPLAYED", "an identical signed action was already recorded"))
        leaf = self.grants.get(gref)
        if leaf is None:
            reasons.append(_r("UNKNOWN_GRANT", gref[:8]))
            return {**res, "verdict": "OUT_OF_AUTHORITY", "reasons": reasons, "warnings": warnings}
        agent_key = leaf["body"]["grantee"]["key"]
        if env.get("signer") != key_id(agent_key):
            reasons.append(_r("WRONG_AGENT_KEY", "action not signed by the key the grant names"))
        elif not envelope_signature_ok(env, agent_key):
            reasons.append(_r("BAD_SIGNATURE", "action signature does not verify"))
        chain, missing = self.chain(gref)
        if missing is not None:
            reasons.append(_r("CHAIN_BROKEN", missing[:8]))
        claimed = body["claimed_at"]
        params, action = body["params"], body["action"]
        for g in self.revoked_in_chain(gref, seq):
            rv = self.revoked[g]
            reasons.append(_r("GRANT_REVOKED", f"{_label(self.grants[g], g)} (revocation {rv['id']} at log position {rv['seq']})"))
        for cref in chain:
            g = self.grants[cref]
            gb, lab = g["body"], _label(g, cref)
            if g["defects"]:
                reasons.append(_r("GRANT_DEFECTIVE", f"{lab}: {', '.join(code_of(x) for x in g['defects'])}"))
            for t_name, t in (("recorded", recorded_at), ("claimed", claimed)):
                if t < gb["not_before"]:
                    reasons.append(_r("GRANT_NOT_YET_VALID", f"{lab} ({t_name} {t} before {gb['not_before']})"))
                if t >= gb["expires_at"]:
                    reasons.append(_r("GRANT_EXPIRED", f"{lab} ({t_name} {t} at or after {gb['expires_at']})"))
            perm = _find_perm(gb, action)
            if perm is None:
                reasons.append(_r("ACTION_NOT_PERMITTED", f"{lab}: '{action}'"))
                continue
            amount = params.get("amount")
            amount_ok = isinstance(amount, int) and not isinstance(amount, bool) and amount >= 0
            if ("amount" in params or "max_amount" in perm or "max_total" in perm) and not amount_ok:
                reasons.append(_r("AMOUNT_MISSING_OR_INVALID", lab))
            if "currency" in perm and params.get("currency") != perm["currency"]:
                reasons.append(_r("CURRENCY_MISMATCH", f"{lab}: {params.get('currency')!r} vs {perm['currency']!r}"))
            if "max_amount" in perm and amount_ok and amount > perm["max_amount"]:
                reasons.append(_r("AMOUNT_OVER_LIMIT", f"{lab}: {amount} > {perm['max_amount']}"))
            if "counterparties" in perm and params.get("counterparty") not in perm["counterparties"]:
                reasons.append(_r("COUNTERPARTY_NOT_ALLOWED", f"{lab}: {params.get('counterparty')!r}"))
            uses, total = self.usage.get((cref, action), [0, 0])
            if "max_uses" in perm and uses + 1 > perm["max_uses"]:
                reasons.append(_r("USES_EXCEEDED", f"{lab}: {uses} used of {perm['max_uses']}"))
            if "max_total" in perm and amount_ok and total + amount > perm["max_total"]:
                reasons.append(_r("CUMULATIVE_LIMIT_EXCEEDED", f"{lab}: {total} + {amount} > {perm['max_total']}"))
        try:
            skew = abs((parse_ts(claimed) - parse_ts(recorded_at)).total_seconds())
            if skew > SKEW_WARN_SECONDS:
                warnings.append(_r("CLAIMED_TIME_SKEW", f"{int(skew)} seconds between claimed and recorded time"))
            if claimed > recorded_at:
                warnings.append(_r("CLAIMED_AFTER_RECORDED"))
        except ValueError:
            reasons.append(_r("TIME_UNPARSEABLE"))
        seen, uniq = set(), []
        for x in reasons:
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        return {**res, "verdict": "OUT_OF_AUTHORITY" if uniq else "IN_AUTHORITY", "reasons": uniq, "warnings": warnings}

    def apply_action(self, env: dict, seq: int, recorded_at: str) -> dict:
        res = self.evaluate_action(env, seq, recorded_at)
        if res["verdict"] == "IN_AUTHORITY":
            # Only a record that was accepted reserves its ref (replay protection). A refused or badly
            # signed copy must not be able to block the genuine record.
            self.action_refs.add(res["ref"])
            body = env["body"]
            chain, _ = self.chain(body["grant"])
            amount = body["params"].get("amount")
            amt = amount if isinstance(amount, int) and not isinstance(amount, bool) else 0
            for cref in chain:
                u = self.usage.setdefault((cref, body["action"]), [0, 0])
                u[0] += 1
                u[1] += amt
        return res


def _safe_id(body):
    if isinstance(body, dict) and isinstance(body.get("id"), str):
        return body["id"]
    return None
