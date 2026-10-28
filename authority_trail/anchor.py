"""Anchoring: tie the log head to an outside clock.

A hash chain alone proves nothing about WHEN, and whoever holds the log can rebuild it. An anchor
commits the head hash to a public ledger, so a later rewrite of earlier entries no longer matches.
Two methods, both optional:

  opentimestamps  Bitcoin, via public calendars. No account, no fee, no wallet. PENDING at first,
                  Bitcoin-attested after confirmation (usually hours).
  ethereum        a self-send transaction on a TEST network whose data field holds the commitment.
                  Needs a funded test wallet (see contrib/eth_send_anchor.py). Checked here by JSON-RPC.

Status labels (a reader must be able to tell these apart):
  CONFIRMED            checked against the outside ledger just now, using a service named by the READER
  ATTESTED_UNCHECKED   the file claims an attestation; nothing outside the file was consulted
  PENDING              a calendar promised to include the hash in Bitcoin; not yet in a block
  UNSUPPORTED          nothing this tool can evaluate
  MISMATCH / INVALID   the anchor does not fit this log, or cannot be read
Only CONFIRMED anchors count as coverage. An anchor stored inside the bundle can be deleted by whoever
holds the bundle: keep your own copy of the head (`head` command, --expect-head) or require an anchor.

The committed bytes are the SHA-256 of a one-line text file (head_text), so the official `ots`
client can verify the same proof from files with no help from this project.
"""
from __future__ import annotations

import json
import os
import urllib.request

from . import ots
from .canon import sha256_hex
from .spec import FORMAT, HEX64

ETH_MARKER = b"AT1"
DEFAULT_ETH_RPC = "https://ethereum-sepolia-rpc.publicnode.com"
BTC_API = "https://blockstream.info/api"
# Test networks only. Anything else is refused, whatever the bundle says.
ETH_TESTNETS = {11155111: "sepolia", 560048: "hoodi", 84532: "base-sepolia"}
MAX_BODY = 1 << 20


def head_text(seq: int, head_hash: str) -> str:
    return f"{FORMAT} head seq={seq} hash={head_hash}\n"


def head_digest(seq: int, head_hash: str) -> bytes:
    return bytes.fromhex(sha256_hex(head_text(seq, head_hash).encode("utf-8")))


def eth_expected_data(seq: int, head_hash: str) -> str:
    return "0x" + (ETH_MARKER + head_digest(seq, head_hash)).hex()


def _text_get(url: str, timeout: int = 20) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "authority-trail/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(MAX_BODY).decode("utf-8")


def _rpc(url: str, method: str, params: list, timeout: int = 20):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": "authority-trail/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out = json.loads(r.read(MAX_BODY).decode("utf-8"))
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


# ---------- create ----------

def new_ots_anchor(seq: int, head_hash: str, ots_bytes: bytes) -> dict:
    return {"method": "opentimestamps", "seq": seq, "head_hash": head_hash, "ots_b64": ots.b64(ots_bytes)}


def new_eth_anchor(seq: int, head_hash: str, tx_hash: str, chain_id: int, network: str) -> dict:
    """The RPC endpoint is deliberately not stored: the reader chooses whom to ask when verifying."""
    return {"method": "ethereum", "network": network, "chain_id": chain_id, "tx_hash": tx_hash,
            "seq": seq, "head_hash": head_hash}


# ---------- check ----------

def check_anchor(a, entries: list, network: bool = False, eth_rpc: str | None = None,
                 text_get=_text_get, rpc=_rpc) -> dict:
    out = {"method": a.get("method") if isinstance(a, dict) else None, "seq": None, "status": "INVALID", "detail": ""}
    if not isinstance(a, dict):
        out["detail"] = "anchor is not an object"
        return out
    seq, hh = a.get("seq"), a.get("head_hash")
    out["seq"] = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
    if not (isinstance(seq, int) and not isinstance(seq, bool) and isinstance(hh, str) and HEX64.match(hh)):
        out["detail"] = "anchor lacks a valid seq or head_hash"
        return out
    if not (0 <= seq < len(entries)) or not isinstance(entries[seq], dict) or entries[seq].get("hash") != hh:
        out["status"] = "MISMATCH"
        out["detail"] = (f"the anchored head hash is not the hash of entry {seq} in this log: earlier entries changed, "
                         "or the anchor belongs to another log")
        return out
    m = a.get("method")
    try:
        if m == "opentimestamps":
            return _check_ots(a, seq, hh, out, network, text_get)
        if m == "ethereum":
            return _check_eth(a, seq, hh, out, network, eth_rpc, rpc)
    except (ots.OtsError, ValueError, KeyError, TypeError) as e:
        out["detail"] = f"proof could not be read: {e}"
        return out
    out["status"] = "UNSUPPORTED"
    out["detail"] = f"unknown anchor method {m!r}"
    return out


def _check_ots(a, seq, hh, out, network, text_get):
    proof = ots.unb64(a["ots_b64"])
    digest, root = ots.parse(proof)
    if digest != head_digest(seq, hh):
        out["status"] = "MISMATCH"
        out["detail"] = "the proof commits to a different digest than this log head"
        return out
    atts = list(ots.attestations(root))
    btc = [x for x in atts if x[0] == "bitcoin"]
    if not btc:
        pend = sorted({x[1] for x in atts if x[0] == "pending"})
        if not pend:
            out["status"] = "UNSUPPORTED"
            out["detail"] = "the proof holds no attestation this tool understands"
            return out
        out["status"] = "PENDING"
        out["detail"] = ("commitment matches the log head; not yet in Bitcoin (calendar promise: " + ", ".join(pend)
                         + "). Complete it later with: python -m authority_trail anchor-upgrade")
        return out
    if not network:
        out["status"] = "ATTESTED_UNCHECKED"
        out["bitcoin_height"] = btc[0][1]
        out["detail"] = (f"proof claims Bitcoin block {btc[0][1]}; no block was looked up (offline). "
                         "Re-run with --network, or verify with the official `ots` client")
        return out
    # Every Bitcoin attestation is tried; one that matches its block is enough.
    last, mismatched = "", ""
    for _, height, msg in btc:
        try:
            bh = text_get(f"{BTC_API}/block-height/{height}").strip()
            blk = json.loads(text_get(f"{BTC_API}/block/{bh}"))
            root_be = bytes.fromhex(blk["merkle_root"])
        except Exception as e:  # network or API trouble is not evidence of tampering
            last = f"Bitcoin block {height} could not be fetched ({type(e).__name__})"
            continue
        if msg == root_be[::-1]:  # explorers print the Merkle root byte-reversed
            out["status"] = "CONFIRMED"
            out["bitcoin_height"] = height
            out["block_time"] = blk.get("timestamp")
            out["detail"] = (f"the proof's final digest equals the Merkle root of Bitcoin block {height} "
                             f"(block explorer: {BTC_API.split('/')[2]}); this log head existed by block time {blk.get('timestamp')} (unix)")
            return out
        mismatched = f"the proof's final digest does not equal the Merkle root of block {height}"
    if mismatched:
        out["status"] = "MISMATCH"
        out["detail"] = mismatched + " (no other Bitcoin attestation in the proof matched either)"
        return out
    out["status"] = "ATTESTED_UNCHECKED"
    out["detail"] = last + "; not confirmed"
    return out


def _check_eth(a, seq, hh, out, network, eth_rpc, rpc):
    cid, name, txh = a.get("chain_id"), a.get("network"), a.get("tx_hash")
    if type(cid) is not int or cid not in ETH_TESTNETS or ETH_TESTNETS[cid] != name:
        out["detail"] = f"only these test networks are accepted: {sorted(ETH_TESTNETS.items())}"
        return out
    if not (isinstance(txh, str) and len(txh) == 66 and txh.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in txh[2:])):
        out["detail"] = "tx_hash must be 0x followed by 64 hex characters"
        return out
    if not network:
        out["status"] = "ATTESTED_UNCHECKED"
        out["detail"] = f"claims {name} transaction {txh}; no node was asked (offline). Re-run with --network"
        return out
    url = eth_rpc or os.environ.get("AUTHORITY_TRAIL_ETH_RPC") or DEFAULT_ETH_RPC
    host = url.split("/")[2] if "//" in url else url
    try:
        got_cid = int(rpc(url, "eth_chainId", []), 16)
        tx = rpc(url, "eth_getTransactionByHash", [txh])
        if tx is None:
            out["status"] = "MISMATCH"
            out["detail"] = f"transaction not found by {host}"
            return out
        blk = rpc(url, "eth_getBlockByNumber", [tx["blockNumber"], False]) if tx.get("blockNumber") else None
        fin = None
        try:
            fin = rpc(url, "eth_getBlockByNumber", ["finalized", False])
        except Exception:
            pass
    except Exception as e:
        out["status"] = "ATTESTED_UNCHECKED"
        out["detail"] = f"RPC lookup at {host} failed ({type(e).__name__}); not confirmed"
        return out
    if got_cid != cid:
        out["status"] = "MISMATCH"
        out["detail"] = f"{host} reports chain {got_cid}, anchor says {cid}"
    elif str(tx.get("hash", "")).lower() != txh.lower():
        out["status"] = "MISMATCH"
        out["detail"] = "the node returned a different transaction than the one asked for"
    elif (tx.get("input") or "").lower() != eth_expected_data(seq, hh):
        out["status"] = "MISMATCH"
        out["detail"] = "transaction data does not carry this log head's commitment"
    elif blk is None:
        out["status"] = "PENDING"
        out["detail"] = "transaction found but not yet in a block"
    elif (str(blk.get("hash", "")).lower() != str(tx.get("blockHash", "")).lower()
          or txh.lower() not in [str(t).lower() for t in blk.get("transactions", [])]):
        out["status"] = "MISMATCH"
        out["detail"] = "the transaction is not listed in the block the node returned for it"
    else:
        ts = int(blk["timestamp"], 16)
        bn = int(blk["number"], 16) if "number" in blk else None
        finalized = bool(fin and bn is not None and bn <= int(fin.get("number", "0x0"), 16))
        out["status"] = "CONFIRMED"
        out["block_time"] = ts
        out["finalized"] = finalized
        out["detail"] = (f"{name} transaction carries this log head's commitment; block time {ts} (unix); "
                         f"{'finalized' if finalized else 'mined, finality not shown'}; answers came from {host}, "
                         "which you are trusting like any node. A test network is a weak clock.")
    return out
