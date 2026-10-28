import hashlib
import json

import pytest

from authority_trail import anchor, ots
from authority_trail.verify import verify_bundle


def pending_tree(uri: str) -> bytes:
    u = uri.encode()
    payload = bytes([len(u)]) + u
    return b"\x00" + ots.ATT_PENDING + bytes([len(payload)]) + payload


def calendar(url, data=None, headers=None, timeout=0):
    base = url.split("/digest")[0]
    return 200, pending_tree(base)


def head_of(trail):
    h = trail.head()
    return h["seq"], h["hash"]


def with_anchor(trail, proof):
    seq, h = head_of(trail)
    b = trail.to_bundle()
    b["anchors"] = [anchor.new_ots_anchor(seq, h, proof)]
    return b


def bitcoin_upgrade(height=800000):
    """A calendar reply that completes a pending attestation: append 8 bytes, sha256, Bitcoin attestation."""
    def upgrader(url, data=None, headers=None, timeout=0):
        att = b"\x00" + ots.ATT_BITCOIN + ots._varbytes(ots._varuint(height))
        return 200, bytes([ots.OP_APPEND, 8]) + b"\x07" * 8 + bytes([ots.OP_SHA256]) + att
    return upgrader


def test_stamp_writes_a_parseable_pending_proof(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    proof = ots.stamp(anchor.head_digest(seq, h), ["https://a.test", "https://b.test"], http=calendar, nonce=b"\x01" * 16)
    digest, root = ots.parse(proof)
    assert digest == anchor.head_digest(seq, h)
    kinds = sorted((k, i) for k, i, _ in ots.attestations(root))
    assert kinds == [("pending", "https://a.test"), ("pending", "https://b.test")]
    assert ots.serialize(digest, root) == proof  # round trip is byte exact


def test_two_calendars_returning_the_same_operation_are_merged_not_duplicated():
    """The official library rejects two identical operations on one node. Replies that share an
    operation must share one edge."""
    def cal(url, data=None, headers=None, timeout=0):
        host = url.split("/digest")[0].encode()
        payload = bytes([len(host)]) + host
        return 200, bytes([ots.OP_SHA256]) + b"\x00" + ots.ATT_PENDING + bytes([len(payload)]) + payload
    proof = ots.stamp(b"\x01" * 32, ["https://a.test", "https://b.test"], http=cal, nonce=b"N" * 16)
    _, root = ots.parse(proof)

    def no_duplicate_edges(node):
        keys = [(op, arg) for op, arg, _ in node.ops]
        assert len(keys) == len(set(keys))
        for _, _, c in node.ops:
            no_duplicate_edges(c)

    no_duplicate_edges(root)
    assert sorted(i for _, i, _ in ots.attestations(root)) == ["https://a.test", "https://b.test"]


def test_pending_anchor_checks_out_but_is_not_coverage(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    b = with_anchor(trail, ots.stamp(anchor.head_digest(seq, h), ["https://a.test"], http=calendar))
    rep = verify_bundle(b)
    assert rep["anchors"][0]["status"] == "PENDING"
    assert rep["unanchored_entries"] == len(b["entries"]) and rep["verified_anchor_seq"] is None
    b2 = json.loads(json.dumps(b))
    b2["anchors"][0]["head_hash"] = b["entries"][2]["hash"]
    b2["anchors"][0]["seq"] = 2
    assert verify_bundle(b2)["anchors"][0]["status"] == "MISMATCH"  # the proof commits to a different digest


def test_unknown_only_proof_is_unsupported_not_pending(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    d = anchor.head_digest(seq, h)
    root = ots.Node(d)
    root.atts.append((b"\x11" * 8, b""))
    rep = verify_bundle(with_anchor(trail, ots.serialize(d, root)))
    assert rep["anchors"][0]["status"] == "UNSUPPORTED" and rep["unanchored_entries"] == len(trail.entries)


def test_removed_or_unconfirmed_anchor_fails_a_required_anchor(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    b = with_anchor(trail, ots.stamp(anchor.head_digest(seq, h), ["https://a.test"], http=calendar))
    for bundle in (b, trail.to_bundle()):
        rep = verify_bundle(bundle, require_anchor=True)
        assert any(f["code"] == "ANCHOR_REQUIRED_NOT_MET" for f in rep["findings"])


def test_upgrade_to_bitcoin_and_online_check(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    proof = ots.stamp(anchor.head_digest(seq, h), ["https://alice.btc.calendar.opentimestamps.org"], http=calendar, nonce=b"\x02" * 16)
    new, n, skipped = ots.upgrade(proof, http=bitcoin_upgrade())
    assert n == 1 and not skipped
    _, root = ots.parse(new)
    btc = [x for x in ots.attestations(root) if x[0] == "bitcoin"]
    assert btc and btc[0][1] == 800000
    final = btc[0][2]
    b = with_anchor(trail, new)
    assert verify_bundle(b)["anchors"][0]["status"] == "ATTESTED_UNCHECKED"

    def good_get(url, timeout=20):
        return "ab" * 32 if "block-height" in url else json.dumps({"merkle_root": final[::-1].hex(), "timestamp": 1700000000})

    a = anchor.check_anchor(b["anchors"][0], b["entries"], network=True, text_get=good_get)
    assert a["status"] == "CONFIRMED" and a["block_time"] == 1700000000

    def bad_get(url, timeout=20):
        return "cd" * 32 if "block-height" in url else json.dumps({"merkle_root": "00" * 32, "timestamp": 1})

    assert anchor.check_anchor(b["anchors"][0], b["entries"], network=True, text_get=bad_get)["status"] == "MISMATCH"

    def down(url, timeout=20):
        raise OSError("offline")

    assert anchor.check_anchor(b["anchors"][0], b["entries"], network=True, text_get=down)["status"] == "ATTESTED_UNCHECKED"


def test_upgrade_only_contacts_known_calendar_hosts(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    proof = ots.stamp(anchor.head_digest(seq, h), ["https://evil.example", "http://alice.btc.calendar.opentimestamps.org"],
                      http=calendar, nonce=b"\x03" * 16)
    contacted = []

    def spy(url, data=None, headers=None, timeout=0):
        contacted.append(url)
        return bitcoin_upgrade()(url)

    new, n, skipped = ots.upgrade(proof, http=spy)
    assert contacted == [] and n == 0 and new == proof
    assert sorted(skipped) == ["alice.btc.calendar.opentimestamps.org", "evil.example"]


def test_a_still_pending_reply_is_not_counted_as_completed(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    proof = ots.stamp(anchor.head_digest(seq, h), ["https://alice.btc.calendar.opentimestamps.org"], http=calendar)
    _, n, _ = ots.upgrade(proof, http=calendar)
    assert n == 0


def test_ots_parser_is_strict():
    base = ots.MAGIC + b"\x01\x08" + b"\x00" * 32
    with pytest.raises(ots.OtsError):
        ots.parse(b"hello")
    with pytest.raises(ots.OtsError):
        ots.parse(ots.MAGIC + b"\x02")
    with pytest.raises(ots.OtsError):
        ots.parse(ots.MAGIC + b"\x01\x08" + b"\x00" * 31)
    with pytest.raises(ots.OtsError):
        ots.parse(ots.MAGIC + b"\x81\x00\x08" + b"\x00" * 32 + b"\x00" + ots.ATT_PENDING + b"\x02\x01a")  # non-minimal version
    with pytest.raises(ots.OtsError):
        ots.parse(base + bytes([ots.OP_APPEND, 0]) + b"\x00" + ots.ATT_PENDING + b"\x02\x01a")  # empty append argument
    with pytest.raises(ots.OtsError):
        ots.parse(base + b"\x00" + ots.ATT_BITCOIN + b"\x02\x01\x00")  # bitcoin payload with trailing byte
    with pytest.raises(ots.OtsError):
        ots.parse(base + b"\x00" + ots.ATT_PENDING + b"\x03\x01a\x00")  # pending payload with trailing byte
    with pytest.raises(ots.OtsError):
        ots.parse(base + b"\x00" + ots.ATT_PENDING + b"\x03\x02a ")  # URI with a disallowed character
    with pytest.raises(ots.OtsError):
        ots.parse(base + b"\x00" + ots.ATT_BITCOIN + b"\x05\xff\xff\xff\xff\x1f")  # height beyond 32 bits
    with pytest.raises(ots.OtsError):
        ots.parse(base + b"\x00" + ots.ATT_PENDING + b"\x02\x01a" + b"\x00")  # trailing bytes
    deep = ots.MAGIC + b"\x01\x08" + b"\x00" * 32 + (bytes([ots.OP_SHA256]) * 300) + b"\x00" + ots.ATT_PENDING + b"\x02\x01a"
    with pytest.raises(ots.OtsError):
        ots.parse(deep)


def test_stamp_fails_closed_when_no_calendar_answers():
    def down(*a, **k):
        return 500, b""
    with pytest.raises(ots.OtsError):
        ots.stamp(b"\x00" * 32, ["https://x.test"], http=down)


def eth_setup(scenario):
    trail, _, _ = scenario
    seq, h = head_of(trail)
    b = trail.to_bundle()
    txh = "0x" + "ab" * 32
    b["anchors"] = [anchor.new_eth_anchor(seq, h, txh, 11155111, "sepolia")]
    data = anchor.eth_expected_data(seq, h)
    blk_hash = "0x" + "cd" * 32

    def rpc_ok(url, method, params, timeout=20):
        if method == "eth_chainId":
            return hex(11155111)
        if method == "eth_getTransactionByHash":
            return {"hash": txh, "input": data, "blockNumber": "0x10", "blockHash": blk_hash}
        if method == "eth_getBlockByNumber":
            if params[0] == "finalized":
                return {"number": "0x20"}
            return {"hash": blk_hash, "number": "0x10", "timestamp": hex(1700000123), "transactions": [txh]}
        raise AssertionError(method)

    return b, data, rpc_ok, txh


def test_ethereum_anchor_checks(scenario):
    b, data, rpc_ok, txh = eth_setup(scenario)
    assert data.startswith("0x415431") and len(data) == 2 + 2 * 35
    assert verify_bundle(b)["anchors"][0]["status"] == "ATTESTED_UNCHECKED"
    a = anchor.check_anchor(b["anchors"][0], b["entries"], network=True, rpc=rpc_ok)
    assert a["status"] == "CONFIRMED" and a["block_time"] == 1700000123 and a["finalized"] is True

    def tweak(method, **fields):
        def rpc(url, m, params, timeout=20):
            r = rpc_ok(url, m, params)
            if m == method and isinstance(r, dict):
                r = {**r, **fields}
            return r
        return rpc

    cases = {
        "wrong data": tweak("eth_getTransactionByHash", input="0x" + "00" * 35),
        "other tx returned": tweak("eth_getTransactionByHash", hash="0x" + "11" * 32),
        "block hash differs": tweak("eth_getBlockByNumber", hash="0x" + "99" * 32),
        "tx not in block": tweak("eth_getBlockByNumber", transactions=["0x" + "77" * 32]),
    }
    for name, rpc in cases.items():
        got = anchor.check_anchor(b["anchors"][0], b["entries"], network=True, rpc=rpc)
        assert got["status"] == "MISMATCH", name

    def wrong_chain(url, m, params, timeout=20):
        return hex(1) if m == "eth_chainId" else rpc_ok(url, m, params)

    assert anchor.check_anchor(b["anchors"][0], b["entries"], network=True, rpc=wrong_chain)["status"] == "MISMATCH"

    def missing(url, m, params, timeout=20):
        return None if m == "eth_getTransactionByHash" else rpc_ok(url, m, params)

    assert anchor.check_anchor(b["anchors"][0], b["entries"], network=True, rpc=missing)["status"] == "MISMATCH"


def test_bundle_cannot_choose_the_ethereum_endpoint(scenario):
    b, data, rpc_ok, txh = eth_setup(scenario)
    b["anchors"][0]["rpc"] = "https://attacker.invalid"
    asked = []

    def spy(url, m, params, timeout=20):
        asked.append(url)
        return rpc_ok(url, m, params)

    anchor.check_anchor(b["anchors"][0], b["entries"], network=True, rpc=spy, eth_rpc="https://reader-chosen.test")
    assert set(asked) == {"https://reader-chosen.test"}
    anchor.check_anchor(b["anchors"][0], b["entries"], network=True, rpc=spy)
    assert "https://attacker.invalid" not in asked


def test_only_known_test_networks_are_accepted(scenario):
    b, data, rpc_ok, txh = eth_setup(scenario)
    for cid, name in ((1, "mainnet"), (11155111, "mainnet"), (17000, "holesky")):
        a = dict(b["anchors"][0], chain_id=cid, network=name)
        assert anchor.check_anchor(a, b["entries"], network=True, rpc=rpc_ok)["status"] == "INVALID"
    bad_tx = dict(b["anchors"][0], tx_hash="0x1234")
    assert anchor.check_anchor(bad_tx, b["entries"], network=True, rpc=rpc_ok)["status"] == "INVALID"


def test_head_text_digest_is_what_the_ots_client_would_hash():
    t = anchor.head_text(5, "ab" * 32)
    assert t == "authority-trail/1 head seq=5 hash=" + "ab" * 32 + "\n"
    assert anchor.head_digest(5, "ab" * 32) == hashlib.sha256(t.encode()).digest()
