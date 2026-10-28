"""Record formats: envelopes, grant/action/revocation bodies, builders and structural validation."""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from . import ed25519
from .canon import canonical, digest, sha256_hex
from .keys import Party, key_id

FORMAT = "authority-trail/1"
DOMAIN = b"authority-trail/1\n"
GENESIS = "0" * 64
KINDS = ("grant", "action", "revocation")
TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SIG_RE = re.compile(r"^[0-9a-f]{128}$")
GRANT_KEYS = {"id", "grantor", "grantee", "parent", "instrument", "purpose", "not_before", "expires_at",
              "permissions", "delegation"}
PERM_KEYS = {"action", "max_amount", "currency", "counterparties", "max_total", "max_uses"}
ACTION_KEYS = {"id", "grant", "action", "params", "claimed_at"}
REVOCATION_KEYS = {"id", "grant", "reason", "claimed_at"}


def now_ts(clock=None) -> str:
    t = clock() if clock else datetime.now(timezone.utc)
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s) -> datetime:
    if not isinstance(s, str) or not TS_RE.match(s):
        raise ValueError(f"bad timestamp {s!r}; use YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def new_id(prefix: str) -> str:
    """A display label with 128 random bits. Labels are never used to look anything up."""
    return f"{prefix}-{os.urandom(16).hex()}"


def ref_of(body: dict) -> str:
    """Content address of a grant, action or revocation body: SHA-256 of its canonical form.
    Records refer to each other by this value, so a label can never be squatted or forged."""
    return digest(body)


# ---------- envelopes ----------

def signing_input(kind: str, body: dict, signer: str) -> bytes:
    return DOMAIN + canonical({"kind": kind, "body": body, "signer": signer})


def make_envelope(party: Party, kind: str, body: dict) -> dict:
    if kind not in KINDS:
        raise ValueError(kind)
    sig = party.sign(signing_input(kind, body, party.key_id))
    return {"kind": kind, "body": body, "signer": party.key_id, "sig": sig.hex()}


def envelope_signature_ok(env: dict, public_hex: str) -> bool:
    """True only if env is signed by exactly this public key (and the key id matches)."""
    try:
        if env.get("signer") != key_id(public_hex):
            return False
        if not (isinstance(env.get("sig"), str) and SIG_RE.match(env["sig"]) and HEX64.match(public_hex)):
            return False
        return ed25519.verify(bytes.fromhex(public_hex),
                              signing_input(env["kind"], env["body"], env["signer"]),
                              bytes.fromhex(env["sig"]))
    except Exception:
        return False


# ---------- builders ----------

def instrument(title: str, text: str) -> dict:
    """The human-readable authorization. Its SHA-256 is signed, so the wording cannot change later."""
    return {"title": title, "text": text, "text_sha256": sha256_hex(text.encode("utf-8"))}


def permission(action: str, *, max_amount=None, currency=None, counterparties=None,
               max_total=None, max_uses=None) -> dict:
    p = {"action": action}
    if max_amount is not None:
        p["max_amount"] = max_amount
    if currency is not None:
        p["currency"] = currency
    if counterparties is not None:
        p["counterparties"] = list(counterparties)
    if max_total is not None:
        p["max_total"] = max_total
    if max_uses is not None:
        p["max_uses"] = max_uses
    return p


def grant_body(grantor: Party, grantee: Party, *, title: str, text: str, purpose: str,
               not_before: str, expires_at: str, permissions: list,
               parent: str | None = None, delegation_max_depth: int = 0,
               grant_id: str | None = None) -> dict:
    """`parent` is the ref (ref_of) of the parent grant body, or None for a root grant."""
    return {
        "id": grant_id or new_id("G"),
        "grantor": grantor.ref(),
        "grantee": grantee.ref(),
        "parent": parent,
        "instrument": instrument(title, text),
        "purpose": purpose,
        "not_before": not_before,
        "expires_at": expires_at,
        "permissions": permissions,
        "delegation": {"allowed": delegation_max_depth > 0, "max_depth": delegation_max_depth},
    }


def action_body(grant_ref: str, action: str, params: dict, claimed_at: str,
                action_id: str | None = None) -> dict:
    """`grant_ref` is ref_of(grant body). `action_id` is a display label."""
    return {"id": action_id or new_id("A"), "grant": grant_ref, "action": action,
            "params": params, "claimed_at": claimed_at}


def revocation_body(grant_ref: str, reason: str, claimed_at: str, rev_id: str | None = None) -> dict:
    return {"id": rev_id or new_id("R"), "grant": grant_ref, "reason": reason, "claimed_at": claimed_at}


# ---------- structural validation (returns a list of problem codes) ----------

def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_pub(v) -> bool:
    """64 lower-case hex characters that encode a valid, non-small-order Ed25519 public key."""
    if not (isinstance(v, str) and HEX64.match(v)):
        return False
    return ed25519.is_valid_public(bytes.fromhex(v))


def _is_ref(v) -> bool:
    return isinstance(v, str) and bool(HEX64.match(v))


def validate_grant_body(b) -> list[str]:
    errs: list[str] = []
    if not isinstance(b, dict):
        return ["GRANT_NOT_OBJECT"]
    for f in ("id", "grantor", "grantee", "parent", "instrument", "purpose", "not_before",
              "expires_at", "permissions", "delegation"):
        if f not in b:
            errs.append(f"GRANT_MISSING_{f.upper()}")
    if errs:
        return errs
    if set(b) - GRANT_KEYS:
        errs.append("GRANT_UNKNOWN_FIELD")
    if not isinstance(b["id"], str) or not ID_RE.match(b["id"]):
        errs.append("GRANT_BAD_ID")
    for who in ("grantor", "grantee"):
        w = b[who]
        if not (isinstance(w, dict) and set(w) == {"name", "key"} and isinstance(w.get("name"), str) and _is_pub(w.get("key"))):
            errs.append(f"GRANT_BAD_{who.upper()}")
    if b["parent"] is not None and not _is_ref(b["parent"]):
        errs.append("GRANT_BAD_PARENT")
    ins = b["instrument"]
    if not (isinstance(ins, dict) and set(ins) == {"title", "text", "text_sha256"} and isinstance(ins.get("text"), str)
            and isinstance(ins.get("title"), str)):
        errs.append("GRANT_BAD_INSTRUMENT")
    elif ins.get("text_sha256") != sha256_hex(ins["text"].encode("utf-8")):
        errs.append("INSTRUMENT_HASH_MISMATCH")
    if not isinstance(b["purpose"], str):
        errs.append("GRANT_BAD_PURPOSE")
    try:
        nb, ex = parse_ts(b["not_before"]), parse_ts(b["expires_at"])
        if not nb < ex:
            errs.append("GRANT_WINDOW_EMPTY")
    except ValueError:
        errs.append("GRANT_BAD_TIME")
    perms = b["permissions"]
    if not isinstance(perms, list) or not perms:
        errs.append("GRANT_NO_PERMISSIONS")
    else:
        seen = set()
        for p in perms:
            if not (isinstance(p, dict) and isinstance(p.get("action"), str) and p["action"]):
                errs.append("PERMISSION_BAD")
                continue
            if set(p) - PERM_KEYS:
                errs.append("PERMISSION_UNKNOWN_FIELD")
            if p["action"] in seen:
                errs.append("PERMISSION_DUPLICATE_ACTION")
            seen.add(p["action"])
            for f in ("max_amount", "max_total", "max_uses"):
                if f in p and not (_is_int(p[f]) and p[f] >= 0):
                    errs.append(f"PERMISSION_BAD_{f.upper()}")
            if "currency" in p and not (isinstance(p["currency"], str) and p["currency"]):
                errs.append("PERMISSION_BAD_CURRENCY")
            if ("max_amount" in p or "max_total" in p) and "currency" not in p:
                errs.append("PERMISSION_AMOUNT_WITHOUT_CURRENCY")
            if "counterparties" in p and not (isinstance(p["counterparties"], list) and p["counterparties"]
                                              and all(isinstance(c, str) for c in p["counterparties"])):
                errs.append("PERMISSION_BAD_COUNTERPARTIES")
    d = b["delegation"]
    if not (isinstance(d, dict) and set(d) == {"allowed", "max_depth"} and isinstance(d.get("allowed"), bool) and _is_int(d.get("max_depth"))
            and d["max_depth"] >= 0 and (d["allowed"] == (d["max_depth"] > 0))):
        errs.append("GRANT_BAD_DELEGATION")
    return errs


def validate_action_body(b) -> list[str]:
    if not isinstance(b, dict):
        return ["ACTION_NOT_OBJECT"]
    errs = []
    for f, t in (("id", str), ("grant", str), ("action", str), ("params", dict), ("claimed_at", str)):
        if not isinstance(b.get(f), t):
            errs.append(f"ACTION_BAD_{f.upper()}")
    if not errs and not _is_ref(b["grant"]):
        errs.append("ACTION_BAD_GRANT_REF")
    if not errs and (not ID_RE.match(b["id"]) or set(b) - ACTION_KEYS or not b["action"]):
        errs.append("ACTION_BAD_ID_OR_FIELD")
    if not errs:
        try:
            parse_ts(b["claimed_at"])
        except ValueError:
            errs.append("ACTION_BAD_TIME")
    return errs


def validate_revocation_body(b) -> list[str]:
    if not isinstance(b, dict):
        return ["REVOCATION_NOT_OBJECT"]
    errs = []
    for f in ("id", "grant", "reason", "claimed_at"):
        if not isinstance(b.get(f), str):
            errs.append(f"REVOCATION_BAD_{f.upper()}")
    if not errs and not _is_ref(b["grant"]):
        errs.append("REVOCATION_BAD_GRANT_REF")
    if not errs and (not ID_RE.match(b["id"]) or set(b) - REVOCATION_KEYS):
        errs.append("REVOCATION_BAD_ID_OR_FIELD")
    if not errs:
        try:
            parse_ts(b["claimed_at"])
        except ValueError:
            errs.append("REVOCATION_BAD_TIME")
    return errs
