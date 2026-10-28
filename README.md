# Authority Trail

**Who let the AI agent do that?** Authority Trail keeps a signed record of what an AI agent was authorised to do, what it asked to do, and what the recorder refused. A lawyer or auditor can re-check that record with a separate, small program instead of taking the operator's word for it.

> Prototype with fictional data. Not legal advice. Nothing here establishes that any grant is legally valid or enforceable, and the recorder is a policy check and a log: it does not move money or stop a tool. See [What this does not establish](#what-this-does-not-establish).

## The problem

An AI agent pays an invoice, approves a transfer or sends a notice. Later someone asks: who authorised this, under what exact wording, up to what limit, until when, and was that authority withdrawn first? Today the answer is usually an application log written by the system being questioned.

## What it does

Three signed record types, one recorder in front of the agent, one independent verifier.

| Record | Signed by | Says |
|---|---|---|
| **Grant** | the key named for the person or organisation giving authority (or for an agent passing part of its authority on) | to whom; the exact plain-language wording (its SHA-256 is signed); a time window; which actions; limits per action, in total and by count; an allowed-counterparty list; whether and how far it may be passed on |
| **Action** | the key named for the agent | which grant it relies on, what it asks to do, with what amount and counterparty |
| **Revocation** | the grantor's key | this grant and everything below it is withdrawn from this point in the log |

The **recorder** checks every requested action against the grants, writes its decision (`ALLOWED` or `BLOCKED`) next to the request, and chains each entry to the one before by hash. Refused requests are kept. The recorder does not execute anything; wiring it in front of a real tool layer is what would make a refusal binding, and that is not built.

The **verifier** rebuilds everything from the saved file and does not trust the recorder's own decisions: hash chain, every signature, every structured limit, expiry, revocation order, and sub-delegation (a downstream agent can never hold more than the agent above it). It prints a plain-text **authority memo** that includes the full signed wording next to the structured limits, because the verifier applies the limits, not the prose, and a person must compare the two.

An **anchor** ties the log head to an outside clock: Bitcoin through OpenTimestamps (no account, no fee, no wallet), or a transaction on an Ethereum test network. Anchors are only one defence. A bundle can have its anchor deleted, so a reader should also keep the head (`head` command, `--expect-head`) somewhere the operator cannot edit.

## Try it (about a minute)

Python 3.11 was used for all testing. The verifier uses only the standard library; `cryptography` is optional (faster, constant-time signing). Run from the repository root, the folder that contains this README. `python examples/quickstart.py` is the shortest tour of the library (a test runs it).

PowerShell:

```powershell
python -m authority_trail demo --out demo_out
$pin = (Get-Content demo_out/PRINCIPAL_KEY_ID.txt).Trim()
python -m authority_trail verify demo_out/trail.json --pin $pin
python -m authority_trail memo   demo_out/trail.json --pin $pin
```

bash:

```sh
python -m authority_trail demo --out demo_out
pin=$(cat demo_out/PRINCIPAL_KEY_ID.txt)
python -m authority_trail verify demo_out/trail.json --pin "$pin"
python -m authority_trail memo   demo_out/trail.json --pin "$pin"
```

The pin here is read from the demo's own output, so it only shows how pin matching works. In real use you get the root key id from the principal through another channel.

Then break it:

```sh
python -m authority_trail tamper demo_out/trail.json --out edited.json              # change one payment amount
python -m authority_trail verify edited.json
#   RESULT: INTEGRITY_FAILED   !! HASH_MISMATCH at entry 1

python -m authority_trail tamper demo_out/trail.json --out sneaky.json --mode rehash   # edit, then rebuild every hash
python -m authority_trail verify sneaky.json
#   RESULT: AUTHORITY_FINDINGS   [HIGH] SIGNATURE_INVALID at entry 1

python -m authority_trail verify demo_out/trail_rogue_operator.json                # operator records an over-limit request as allowed
#   [HIGH] ALLOWED_OUTSIDE_AUTHORITY at entry 14
```

Or open `web/verify.html` in a recent browser, drop `trail.json` on it, and press the edit button. It checks the hash chain and the signatures locally and nothing is uploaded; it does not apply the authority rules.

`examples/quickstart.py` shows the library in about 40 lines. A committed sample log is in `examples/sample/`.

### The scenario in the demo

A fictional company authorises a LegalOps Agent for one week: pay invoices to two named firms (USD 5,000 each, USD 12,000 in total), approve transfers of fund units to two listed investors (1,000 each, 2,500 in total), send up to 10 notices. The agent passes "send notices, at most 3" to a Filing Agent. Then, in log order: two requests within the limits; a payment over the per-invoice limit (refused); a transfer to an unlisted counterparty (refused); the Filing Agent asking to pay (refused, never delegated); two payments within limits and a third that would pass the total (refused); the company revokes; both agents try again (refused, authority withdrawn). The investor list is just a list of names in the grant; no investor verification is implemented.

## What the verifier checks

- Hash chain: sequence numbers, previous-hash links, recomputed hashes, valid recorded times in order.
- Every signature against the key the grant names; keys that are small-order curve points are refused.
- The signed wording against its signed hash.
- For each requested action: right key, inside the window (both recorded and claimed time), permission exists, amount, currency, counterparty list, count, running total, no earlier revocation, sound grant chain, no identical replay.
- For each sub-grant: signed by the parent's grantee, delegation allowed and within depth, narrower than the parent in every respect (every condition the parent states must be restated, no looser).
- Whether the recorder's `ALLOWED` or `BLOCKED` matches the verifier's own verdict.
- The root key against keys you pinned from an outside source (`--pin`), your saved head (`--expect-head`), and, if you ask, a confirmed anchor (`--require-anchor`).

Records refer to each other by the SHA-256 of their content, never by label, and a copy that is not correctly signed or not accepted reserves nothing, so nobody can squat a label or submit a look-alike first to block a genuine grant, action or revocation. Grants with unknown or misspelled fields are refused rather than silently ignored.

## Anchoring

```sh
python -m authority_trail head demo_out/trail.json                # SEQ:HASH; keep it where the operator cannot edit it
python -m authority_trail anchor-stamp demo_out/trail.json        # sends one 32-byte hash to public OpenTimestamps calendars
python -m authority_trail verify demo_out/trail.json              # anchor shows PENDING (not counted as coverage)
# some hours later, once Bitcoin has confirmed:
python -m authority_trail anchor-upgrade demo_out/trail.json
python -m authority_trail verify demo_out/trail.json --network    # looks up the Bitcoin block; CONFIRMED
python -m authority_trail anchor-export demo_out/trail.json --dir anchor_files   # then: ots verify anchor_files/head_13.txt.ots
```

Status labels: `CONFIRMED` (checked against the outside ledger just now), `ATTESTED_UNCHECKED` (the file claims it; nothing outside was consulted), `PENDING` (a calendar promise, not yet in Bitcoin), `UNSUPPORTED`, `MISMATCH`, `INVALID`. Only `CONFIRMED` counts as coverage. The Ethereum RPC endpoint and the Bitcoin explorer are chosen by the reader (`--eth-rpc`, built-in explorer URL), never by the bundle, and a `CONFIRMED` result is only as good as the service asked. `anchor-upgrade` contacts only a short built-in list of well-known OpenTimestamps calendars.

Ethereum test network (optional; needs a throwaway funded test wallet and `pip install eth-account`): `contrib/eth_send_anchor.py`. It refuses any network that is not a listed test network.

## What this does not establish

- That the signed wording and the structured limits say the same thing. The verifier applies the structured limits.
- That a grant is legally valid or enforceable, or that anyone had capacity or power to give it.
- That a key belongs to a named person or organisation. `--pin` narrows this: you supply a key id you obtained elsewhere.
- That anything was executed or prevented. `allowed` and `refused` are what the recorder reported. Limits on totals and counts count requests judged within limits, not money moved.
- That the facts inside an action are true (that an invoice was real, say).
- That nothing is missing from the log. A record the operator never wrote cannot be seen. Principals should keep their own signed copies and their own saved head.
- How a court or regulator would treat these records. Electronic-signature law differs by jurisdiction and is not assessed.

Other limits are in [docs/DESIGN.md](docs/DESIGN.md): prototype status, no key rotation, one recorder, a pure-Python reference signer that is not constant time, no concurrent writers, records are not bound to a particular log, test-network Ethereum only.

## How it was checked

`python -m pytest` runs 81 tests in a few minutes (five need Node, one compares against the `cryptography` package and is skipped if it is absent).

- Cryptography: Ed25519 matches two RFC 8032 test vectors and, in 5 random trials, the `cryptography` package; malformed keys, signatures and all eight small-order points are rejected.
- Rules: unit tests for each refusal reason, sub-delegation narrowing, shared budgets up the chain, revocation rights and order versus claimed time, wrong signer, forged grant, label squatting, replay, missing or mistyped amount and currency (fail closed), caller mutation of recorder state.
- Tamper detection, measured on the demo log: 240 single-field edits, 0 missed (each breaks the hash chain); 106 edits to signed content of allowed entries with every hash rebuilt, 0 missed (a signature or a rule breaks). These are regression tests written by the same author as the code, not an independent evaluation. A documented limit: rebuilding the chain after editing only unsigned fields (the recorder's decision, the recorded time) is invisible to the verifier alone; it is caught by an anchor made earlier or by a head you saved, and both are tested.
- Robustness: 960 type-confusion mutations of the demo log; the verifier always returned a report, and every mutation that actually changed the file was reported as a failure (one of the 960 replaced a value with an equal one, a no-op). Over 500 more mutations, some carrying text meant to forge memo sections, are rendered through the memo, which must neither crash nor print a second findings or limits section. A hostile or oversized file gives a plain error, not a crash.
- Two implementations: `web/verify.html` re-implements canonical JSON, hashing and signature checks in JavaScript; tests run it under Node against the Python verifier, including non-ASCII text, key ordering and small-order key encodings that Web Crypto itself would accept. The Python verifier always uses its own pure-Python Ed25519 check for this reason; the `cryptography` package is used for signing only.
- OpenTimestamps: during development, proofs written by `authority_trail/ots.py` (including one merged from two live calendars) were parsed by the official `opentimestamps` Python library, and a proof re-serialised by that library was read back here. That was done by hand, not in the test suite. The Bitcoin-block lookup is tested with synthetic proofs and a mocked block API; its byte-order assumption (the proof's digest equals the explorer's Merkle root reversed) was checked by hand against the raw header of Bitcoin block 800000. As of the commit date it has not been run against a confirmed Bitcoin proof of this project's own.
- Ethereum: transaction signing was checked offline during development; the verifier's RPC lookup is tested against a mocked node. No live broadcast has been run from this repository.

## What existed before, what is new

The author had an earlier private prototype for approving agent payments, with a symmetric-key (HMAC) receipt chain. Authority Trail reuses the ideas of canonical JSON, hash chaining and naming the first broken record, and nothing else: no code was copied. Everything in this repository, including asymmetric signatures (so a third party can verify without holding a secret), delegation chains, revocation ordering, the recorder, the verifier, the memo, anchoring and the browser checker, was written for this hackathon starting 27 October 2026. `authority_trail/ed25519.py` is adapted from the reference code in RFC 8032; see [NOTICE](NOTICE).

## Layout

```
authority_trail/   canon, ed25519 (pure Python), keys, spec, evaluate (the rules), trail (recorder),
                   verify, memo, anchor, ots, demo, cli
web/verify.html    browser checker (hash chain and signatures only)
contrib/           eth_send_anchor.py (optional, test networks only)
examples/          quickstart.py, sample/ (a recorded run)
scripts/           demo_walkthrough.py, embed_sample.py
docs/DESIGN.md     formats, rules, threat table, limits
tests/
```

## How it was made

LLM-assisted development that I specified, directed and reviewed. The tests above are there so that you do not have to take that on trust.

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
