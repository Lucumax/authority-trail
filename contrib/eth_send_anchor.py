#!/usr/bin/env python3
"""Anchor a log head on an Ethereum TEST network with a 0-value self-send whose data field is the commitment.

Optional helper, not part of the verifier. Needs:  pip install eth-account
Use a throwaway test wallet funded from a faucet. NEVER put a key that holds real funds in the environment.

    set ANCHOR_ETH_KEY=0x<throwaway testnet private key>        (PowerShell: $env:ANCHOR_ETH_KEY="0x...")
    python contrib/eth_send_anchor.py demo_out/trail.json --rpc https://ethereum-sepolia-rpc.publicnode.com
    python -m authority_trail anchor-eth-record demo_out/trail.json --tx 0x<hash printed above>
    python -m authority_trail verify demo_out/trail.json --network

Mainnet and unknown networks are refused: only the test chain ids below are allowed.
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from authority_trail import anchor  # noqa: E402

from authority_trail.anchor import ETH_TESTNETS as TESTNETS  # noqa: E402


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "authority-trail/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read().decode())
    if "error" in out:
        raise SystemExit(f"RPC error from {method}: {out['error']}")
    return out["result"]


def build_signed_tx(private_key, chain_id, nonce, data_hex, max_fee, max_priority, gas=60000):
    from eth_account import Account
    acct = Account.from_key(private_key)
    tx = {"type": 2, "chainId": chain_id, "nonce": nonce, "to": acct.address, "value": 0, "gas": gas,
          "maxFeePerGas": max_fee, "maxPriorityFeePerGas": max_priority, "data": data_hex}
    signed = Account.sign_transaction(tx, private_key)
    return acct.address, signed.raw_transaction, "0x" + signed.hash.hex().removeprefix("0x")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--rpc", default=anchor.DEFAULT_ETH_RPC)
    a = ap.parse_args()
    key = os.environ.get("ANCHOR_ETH_KEY")
    if not key:
        raise SystemExit("set ANCHOR_ETH_KEY to a throwaway TESTNET key (see the header of this file)")
    with open(a.bundle, encoding="utf-8") as f:
        bundle = json.load(f)
    e = bundle["entries"][-1]
    data = anchor.eth_expected_data(e["seq"], e["hash"])
    chain_id = int(rpc(a.rpc, "eth_chainId", []), 16)
    if chain_id not in TESTNETS:
        raise SystemExit(f"chain id {chain_id} is not an allowed test network {sorted(TESTNETS)}; refusing")
    from eth_account import Account
    addr = Account.from_key(key).address
    nonce = int(rpc(a.rpc, "eth_getTransactionCount", [addr, "pending"]), 16)
    base = int(rpc(a.rpc, "eth_gasPrice", []), 16)
    prio = max(int(1.5e9), 0)
    addr, raw, txh = build_signed_tx(key, chain_id, nonce, data, base * 2 + prio, prio)
    print(f"network {TESTNETS[chain_id]} (chain {chain_id}); from/to {addr}; data {data}")
    sent = rpc(a.rpc, "eth_sendRawTransaction", ["0x" + raw.hex().removeprefix("0x")])
    print(f"sent. tx hash: {sent}")
    print(f"next: python -m authority_trail anchor-eth-record {a.bundle} --tx {sent} --chain-id {chain_id} --network-name {TESTNETS[chain_id]}")


if __name__ == "__main__":
    main()
