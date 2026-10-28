# Design and format

This file is the specification a second implementation would follow. `web/verify.html` is a partial one: it re-implements canonical JSON, hashing and signature checks in JavaScript (not the authority rules or anchors), and `tests/test_web.py` checks that it agrees with the Python verifier on those checks.

## 1. Roles

| Role | Does | Holds |
|---|---|---|
| Grantor | Signs a grant: who may do what, for how long, within what limits. The first grantor (the root) is the person or organisation the authority comes from. A grantee that may sub-delegate is also the grantor of the sub-grant. | Ed25519 private key |
| Grantee (the agent) | Signs each action it requests. | Ed25519 private key |
| Recorder | Runs beside the agent. Checks each submitted record against the rules, appends it to the log with its decision (`ALLOWED` or `BLOCKED`), chains the entry to the previous one. Blocked requests are kept. It does not execute actions or intercept tools. | The log |
| Verifier | Reads a saved log, trusts nothing in it, recomputes everything. Standard library only. | Nothing |
| Anchor | A public ledger that holds a commitment to the log head: Bitcoin through OpenTimestamps, or an Ethereum test network. | n/a |

## 2. Bytes that are hashed and signed

Canonical JSON (`authority_trail/canon.py`): object keys sorted by Unicode code point, no whitespace, UTF-8, integers only and within +/- (2^53 - 1) so JavaScript and Python agree (floats and larger integers are refused). Money is integer minor units (cents). Strings must be valid Unicode (lone surrogates are refused).

- Key id: first 32 hex characters of SHA-256 of the raw 32-byte public key.
- Envelope: `{"kind": "grant"|"action"|"revocation", "body": {...}, "signer": <key id>, "sig": <hex>}`.
- Signature: Ed25519 over the bytes `"authority-trail/1\n" || canonical({"kind","body","signer"})`.
- Ref: `ref = SHA-256(canonical(body))` for a grant, action or revocation body. **Records refer to each other by ref, never by label.** `action.grant`, `revocation.grant` and `grant.parent` hold the ref of the grant body. The `id` field is a display label with no uniqueness meaning, so a label cannot be squatted.
- Log entry: `{"seq", "prev", "recorded_at", "envelope", "gate", "hash"}` with `hash = SHA-256(canonical(entry without "hash"))`, `prev` the previous entry's hash (64 zeros for the first), `seq` an integer starting at 0.
- Bundle: `{"format": "authority-trail/1", "entries": [...], "anchors": [...]}`.
- Timestamps: `YYYY-MM-DDTHH:MM:SSZ`, UTC, and they must be real calendar times.

## 3. Records

Grant body: `id`, `grantor {name,key}`, `grantee {name,key}`, `parent` (ref or null), `instrument {title, text, text_sha256}`, `purpose`, `not_before`, `expires_at` (end excluded), `permissions[]`, `delegation {allowed, max_depth}`.
A permission: `action` plus optional `max_amount`, `currency`, `counterparties[]`, `max_total`, `max_uses`. A permission with `max_amount` or `max_total` must name a `currency`.
Public keys must be valid, canonical, non-small-order Ed25519 points. Unknown fields in a grant, permission, delegation or instrument make the grant defective (a misspelled limit must not silently disappear), currency strings and counterparty lists must not be empty, and ids of grants, actions and revocations must match `[A-Za-z0-9._-]{1,64}`. Signatures are exactly 128 lower-case hex characters.

Action body: `id`, `grant` (ref), `action`, `params {amount, currency, counterparty, ...}`, `claimed_at`.
Revocation body: `id`, `grant` (ref), `reason`, `claimed_at`.

`instrument.text` is the plain-language wording a person would read. Its SHA-256 is inside the signed body, so the wording shown in a memo is the wording that was signed. **Nothing checks that the wording and the structured permissions agree.** The verifier applies the structured permissions; a reader must compare them with the wording, and the memo prints both for that reason.

## 4. The authority rules (`authority_trail/evaluate.py`)

The recorder and the verifier use the same function, but the verifier replays the log itself and never trusts the recorder's `gate` field. A bug in the shared rules would be a bug in both; tests state expected outcomes independently of the code (`tests/test_authority.py`).

An action is `IN_AUTHORITY` only if all of these hold, for the grant it names and every ancestor grant up to the root:

1. The action is signed by the key the grant names as grantee.
2. No revocation of that grant or an ancestor sits earlier in the log. Log order decides, not any claimed time.
3. Both the recorded time and the claimed time are inside `[not_before, expires_at)`.
4. The grant has a permission for that action name.
5. If the permission names a currency, the action's currency equals it (always, even when the amount is unusable). Amount present and an integer >= 0 when the permission has `max_amount` or `max_total`, and not over `max_amount`. Counterparty on the list if the permission has one (a missing counterparty fails). Uses so far below `max_uses`. Running total plus this amount not over `max_total`.
6. The grant itself is sound (not defective).
7. The identical signed action was not recorded before.

Every constraint missing from an action fails closed.

**Budgets count requests, not money.** `max_uses` and `max_total` are charged when a request is judged in authority. Nothing here sees whether a payment happened, so an out-of-authority request that was recorded as allowed (and perhaps executed) consumes no budget in the replay. When the verifier finds such a request it sets `budget_caveat` and reports `BUDGET_ACCOUNTING_CONDITIONAL`: later "within limits" verdicts that depend on totals are conditional. A real deployment would need authenticated execution receipts to turn this into a spend ledger; that is not built. Budgets are shared up the chain: what a downstream agent is judged to use counts against its parents too.

A sub-grant is sound only if: it is signed by the parent's grantee; the parent allows delegation and has depth to spare; the parent was in force and not revoked when the sub-grant was recorded; and it narrows the parent. Narrowing: window inside the parent's; for each permission the parent states, the child restates it no looser (same currency, `max_amount`/`max_total`/`max_uses` present and not higher, counterparty list present and a subset).

A revocation is effective only if signed by the grantor of the grant or of one of its ancestors. It affects everything recorded after it, including descendant grants. A revocation recorded before the grant it names is ineffective (the target is unknown at that point). A revocation or action that fails its checks reserves nothing: only an accepted action reserves its ref (replay protection), a revocation reserves its ref only when effective, and a grant copy that is not signed by its named grantor is not stored at all. A sound copy of a grant replaces an earlier defective copy of the same body (for example one replayed before its parent existed).

## 5. What the verifier reports

- Chain: integer sequence numbers, `prev` links, recomputed hashes, valid and non-decreasing recorded times, known record kinds. Any problem makes the status `INTEGRITY_FAILED`.
- For every record: verdict and reason codes. For every request the recorder allowed (or whose recorder decision is missing or malformed): does the verifier agree? `ALLOWED_OUTSIDE_AUTHORITY`, `SIGNATURE_INVALID`, `REVOCATION_NOT_EFFECTIVE` and `GATE_MALFORMED` are high findings. A refused request whose signature does not verify is reported as `REFUSED_REQUEST_NOT_AUTHENTICATED` (informational).
- Pinned keys: with `--pin`, each root grantor key must match a key id or public key you obtained elsewhere. Without it the memo says the key binding was not checked.
- Saved head: `--expect-head SEQ:HASH` must be found in the log. This is how a reader detects a log that was shortened or rebuilt, including one whose anchor was deleted.
- Anchors: each anchor must commit to the hash of the entry it names; only `CONFIRMED` anchors count as coverage; `--require-anchor` fails if none is confirmed.

Exit codes: 0 clean (including clean with warnings), 1 integrity failed, 3 authority findings, 2 usage or read error.

## 6. Anchors

The committed bytes are the SHA-256 of one line of text, `authority-trail/1 head seq=<n> hash=<hex>\n`. That makes the proof checkable by the official OpenTimestamps client from two files (`anchor-export` writes them) with no help from this project. `ots.py` reads and writes standard `.ots` files with limits that follow the official library (argument and message sizes, attestation payload sizes, URI characters, recursion depth); identical operations from several calendars are merged into one edge.

`anchor-upgrade` contacts only a built-in list of well-known calendar hosts over HTTPS and ignores any other host named inside a proof. A pending reply does not count as completed.

For Ethereum the anchor is a zero-value self-send on a **test network** (listed chain ids only) whose data field is `0x415431` (ASCII "AT1") followed by that SHA-256. The verifier looks the transaction up over JSON-RPC at an endpoint the reader chooses (`--eth-rpc`, environment variable, or a public default), never one named in the bundle, and checks: chain id, transaction hash, input data, block hash, that the block lists the transaction, and whether the block is at or below the node's finalized block. A `CONFIRMED` result is only as trustworthy as the node asked.

An anchor stored in the bundle can be deleted by whoever holds the bundle. It proves something only to a reader who looks for it (`--require-anchor`) or who also saved the head elsewhere.

## 7. Threat table

| Attack | Result |
|---|---|
| Edit any field of any entry | Hash mismatch at that entry; the report names the earliest broken entry. |
| Edit a signed field and rebuild every hash after it | Chain looks intact; the edited record's signature fails (or its reference no longer resolves); an earlier anchor or saved head no longer matches. |
| Edit only unsigned fields (`gate`, `recorded_at`) and rebuild the hashes | Not visible to the verifier alone. Visible against an earlier confirmed anchor or a saved head. This is why anchoring and saved heads matter. |
| Delete the anchor from a bundle and rebuild | A reader who requires an anchor, or who saved the head, sees it. A reader who does neither does not. |
| Operator records an out-of-authority request as `ALLOWED` | Verifier re-evaluates and reports `ALLOWED_OUTSIDE_AUTHORITY`. |
| Agent exceeds limits, uses another key, acts after expiry or revocation | Refused by the recorder, kept on record, re-checked by the verifier. |
| Sub-agent asks for wider powers than its parent | Sub-grant is defective; actions under it are out of authority. |
| Someone reuses a label, or submits an exact copy of a genuine record first with a bad signature | Nothing is looked up by label; refs are content hashes; a badly signed or refused copy reserves nothing. |
| Grant names a small-order key as the agent | Grant is defective; verification of such keys is refused. |
| Caller edits a record object after submitting it | The recorder keeps its own copy. |
| Operator never writes a record (for example a revocation) | Not detectable from the log. Principals should keep their own signed copies and a saved head. |
| Signed records copied into another log | Possible: records are not bound to a particular log. Each log has its own history; a verifier reads one bundle. |
| Stolen private key | Out of scope. Whoever holds the key can sign. |
| Wrong person behind a key | Out of scope. Pinning a key you got elsewhere narrows this; it does not solve identity. |

## 8. Known limits

- Prototype. No independent security review. The pure-Python Ed25519 signer is the RFC 8032 reference algorithm and is not constant time; the `cryptography` package is used for signing when installed. Use a vetted library or a hardware key in any real deployment. Verification follows RFC 8032 with extra refusal of small-order public keys.
- Log order is what the recorder wrote. A single recorder is a single point of trust until anchors or saved heads are frequent.
- No key rotation, no key revocation list, no expiry of keys.
- Rules cover amount, currency, counterparty, count, cumulative total, window, delegation. They do not model conditions such as "only if a second person approves", and they cannot check the prose of an instrument.
- Time: `recorded_at` is the recorder's clock. A confirmed anchor gives an upper bound on when the log head existed; it does not prove the time of any single action. Signatures do not cover the recorded time or the sequence position.
- The recorder is not safe for concurrent writers.
- The browser page checks hash chain and signatures only, refuses non-integer numbers, small-order key encodings (including non-canonical ones) and non-canonical signature hex; it keeps the first record of an exact grant, as the Python verifier does. It reports an action recorded before its grant as not valid, where the Python verifier reports an unknown grant.
- Memo and command-line output print bundle-sourced text with control characters replaced, so a submitted record cannot forge memo sections; verdict labels in the memo are format and rule checks, not legal conclusions.
- Ethereum anchoring uses test networks only. Bitcoin proofs start PENDING and need hours to confirm.
- Not legal advice. Nothing here establishes that a grant is valid or enforceable or that a signature has legal effect anywhere.
