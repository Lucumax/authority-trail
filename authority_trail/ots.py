"""Minimal OpenTimestamps (.ots) reader, writer, stamper and upgrader. Standard library only.

OpenTimestamps commits a SHA-256 digest into Bitcoin through public calendar servers. A proof starts
as PENDING (calendar promise) and is upgraded to a Bitcoin block attestation after confirmation,
usually within hours. This module writes standard .ots files that the official `opentimestamps`
Python library parses (checked by hand during development; see README).

Limits mirror the official implementation where known: operation arguments 1 to 4096 bytes,
messages at most 4096 bytes, attestation payloads at most 8192 bytes, calendar URIs at most 1000
characters from a restricted set, recursion depth 256. Extra limits: 1 MiB per proof, 20000 nodes.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import urllib.parse
import urllib.request

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OP_SHA256, OP_APPEND, OP_PREPEND = 0x08, 0xF0, 0xF1
ATT_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
ATT_BITCOIN = bytes.fromhex("0588960d73d71901")
DEFAULT_CALENDARS = ["https://alice.btc.calendar.opentimestamps.org",
                     "https://bob.btc.calendar.opentimestamps.org"]
# Hosts an upgrade will contact. A proof that names any other host is skipped, never followed:
# the file being checked must not be able to point this tool at an arbitrary server.
ALLOWED_CALENDAR_HOSTS = {"alice.btc.calendar.opentimestamps.org", "bob.btc.calendar.opentimestamps.org",
                          "finney.calendar.eternitywall.com", "ots.btc.catallaxy.com"}
MAX_DEPTH = 256
MAX_MSG = 4096
MAX_PAYLOAD = 8192
MAX_URI = 1000
MAX_PROOF_BYTES = 1 << 20
MAX_NODES = 20000
_URI_OK = re.compile(r"^[a-zA-Z0-9.\-_/:]+$")


class OtsError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self.d, self.i, self.nodes = data, 0, 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.d):
            raise OtsError("truncated proof")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def byte(self) -> int:
        return self.read(1)[0]

    def varuint(self) -> int:
        v, shift, n = 0, 0, 0
        while True:
            b = self.byte()
            n += 1
            v |= (b & 0x7F) << shift
            if not b & 0x80:
                if n > 1 and b == 0:
                    raise OtsError("non-minimal integer encoding")
                return v
            shift += 7
            if n >= 9:
                raise OtsError("integer too long")

    def varbytes(self, limit: int) -> bytes:
        n = self.varuint()
        if n > limit:
            raise OtsError("field too large")
        return self.read(n)

    def eof(self) -> bool:
        return self.i >= len(self.d)


def _varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _varbytes(b: bytes) -> bytes:
    return _varuint(len(b)) + b


def _apply(op: int, arg: bytes, msg: bytes) -> bytes:
    if op == OP_SHA256:
        out = hashlib.sha256(msg).digest()
    elif op == OP_APPEND:
        out = msg + arg
    elif op == OP_PREPEND:
        out = arg + msg
    else:
        raise OtsError(f"unsupported operation 0x{op:02x}")
    if len(out) > MAX_MSG:
        raise OtsError("intermediate message too long")
    return out


class Node:
    """A message plus the attestations and operations that hang off it."""

    def __init__(self, msg: bytes):
        self.msg = msg
        self.atts: list[tuple[bytes, bytes]] = []        # (tag, payload)
        self.ops: list[tuple[int, bytes, "Node"]] = []   # (op, arg, child)


def _parse_tree(r: _Reader, msg: bytes, depth: int = 0) -> Node:
    if depth > MAX_DEPTH:
        raise OtsError("proof too deep")
    node = Node(msg)
    while True:
        r.nodes += 1
        if r.nodes > MAX_NODES:
            raise OtsError("proof too large")
        tag = r.byte()
        more = tag == 0xFF
        if more:
            tag = r.byte()
        if tag == 0x00:
            att = (r.read(8), r.varbytes(MAX_PAYLOAD))
            _check_attestation(*att)
            node.atts.append(att)
        else:
            if tag in (OP_APPEND, OP_PREPEND):
                arg = r.varbytes(MAX_MSG)
                if not arg:
                    raise OtsError("empty operation argument")
            else:
                arg = b""
            node.ops.append((tag, arg, _parse_tree(r, _apply(tag, arg, msg), depth + 1)))
        if not more:
            return node


def _check_attestation(tag: bytes, payload: bytes) -> None:
    """Reject known attestation types whose payload is malformed. Unknown tags pass through untouched."""
    if tag == ATT_PENDING:
        rr = _Reader(payload)
        uri = rr.varbytes(MAX_URI)
        if not rr.eof() or not uri or not _URI_OK.match(uri.decode("ascii", "replace")):
            raise OtsError("malformed pending attestation")
    elif tag == ATT_BITCOIN:
        rr = _Reader(payload)
        h = rr.varuint()
        if not rr.eof() or h >= 1 << 32:
            raise OtsError("malformed bitcoin attestation")


def parse(ots: bytes):
    """Return (digest, root Node). Raises OtsError for anything it does not understand."""
    if len(ots) > MAX_PROOF_BYTES:
        raise OtsError("proof too large")
    r = _Reader(ots)
    if r.read(len(MAGIC)) != MAGIC:
        raise OtsError("not an OpenTimestamps proof")
    if r.varuint() != 1:
        raise OtsError("unsupported proof version")
    if r.byte() != OP_SHA256:
        raise OtsError("only SHA-256 proofs are supported")
    digest = r.read(32)
    root = _parse_tree(r, digest)
    if not r.eof():
        raise OtsError("trailing bytes after proof")
    return digest, root


def _serialize_tree(node: Node) -> bytes:
    items = []
    for tag, payload in node.atts:
        items.append(b"\x00" + tag + _varbytes(payload))
    for op, arg, child in node.ops:
        items.append(bytes([op]) + (_varbytes(arg) if op in (OP_APPEND, OP_PREPEND) else b"") + _serialize_tree(child))
    if not items:
        raise OtsError("empty timestamp node")
    return b"".join((b"\xff" if i < len(items) - 1 else b"") + it for i, it in enumerate(items))


def serialize(digest: bytes, root: Node) -> bytes:
    return MAGIC + _varuint(1) + bytes([OP_SHA256]) + digest + _serialize_tree(root)


def merge(into: Node, other: Node) -> None:
    """Merge `other` into `into` the way the official library does: identical operations share one edge,
    identical attestations appear once."""
    for att in other.atts:
        if att not in into.atts:
            into.atts.append(att)
    for op, arg, child in other.ops:
        for op2, arg2, child2 in into.ops:
            if op2 == op and arg2 == arg:
                merge(child2, child)
                break
        else:
            into.ops.append((op, arg, child))


def attestations(root: Node):
    """Yield (kind, info, msg): kind is 'pending' (info = calendar uri), 'bitcoin' (info = height) or 'unknown'."""
    stack = [root]
    while stack:
        n = stack.pop()
        for tag, payload in n.atts:
            if tag == ATT_PENDING:
                yield ("pending", _Reader(payload).varbytes(MAX_URI).decode("ascii"), n.msg)
            elif tag == ATT_BITCOIN:
                yield ("bitcoin", _Reader(payload).varuint(), n.msg)
            else:
                yield ("unknown", tag.hex(), n.msg)
        stack.extend(c for _, _, c in n.ops)


# ---------- network (stamp and upgrade) ----------

MAX_RESPONSE = 1 << 16


def _http(url: str, data: bytes | None = None, headers: dict | None = None, timeout: int = 20):
    if urllib.parse.urlparse(url).scheme != "https":
        raise OtsError("only https calendar URLs are used")
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_RESPONSE + 1)[:MAX_RESPONSE]
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_RESPONSE + 1)[:MAX_RESPONSE]


HEADERS = {"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "authority-trail/0.1",
           "Content-Type": "application/x-www-form-urlencoded"}


def _parse_reply(body: bytes, msg: bytes, depth: int) -> Node:
    r = _Reader(body)
    node = _parse_tree(r, msg, depth)
    if not r.eof():
        raise OtsError("trailing bytes in calendar reply")
    return node


def stamp(digest: bytes, calendars=None, http=_http, nonce: bytes | None = None) -> bytes:
    """Submit digest (via a random nonce, as the official client does) to calendars; return .ots bytes.
    Only a hash leaves this machine."""
    if len(digest) != 32:
        raise OtsError("digest must be 32 bytes")
    nonce = nonce if nonce is not None else os.urandom(16)
    committed = hashlib.sha256(digest + nonce).digest()
    sha_node = Node(committed)
    got = 0
    for cal in (calendars or DEFAULT_CALENDARS):
        try:
            status, body = http(cal.rstrip("/") + "/digest", committed, HEADERS)
            if status != 200:
                continue
            merge(sha_node, _parse_reply(body, committed, 3))
        except Exception:
            continue
        got += 1
    if not got:
        raise OtsError("no calendar accepted the digest")
    root = Node(digest)
    app = Node(digest + nonce)
    app.ops.append((OP_SHA256, b"", sha_node))
    root.ops.append((OP_APPEND, nonce, app))
    return serialize(digest, root)


def upgrade(ots: bytes, http=_http, allowed_hosts=None) -> tuple[bytes, int, list]:
    """Replace pending attestations that a calendar can now complete with Bitcoin attestations.
    Only calendars in allowed_hosts are contacted. Returns (new bytes, number completed, skipped hosts)."""
    allowed = set(allowed_hosts) if allowed_hosts is not None else set(ALLOWED_CALENDAR_HOSTS)
    digest, root = parse(ots)
    done, skipped = 0, []

    def walk(n: Node, depth: int):
        nonlocal done
        for _, _, ch in list(n.ops):
            walk(ch, depth + 1)
        for att in list(n.atts):
            if att[0] != ATT_PENDING:
                continue
            uri = _Reader(att[1]).varbytes(MAX_URI).decode("ascii")
            parts = urllib.parse.urlparse(uri)
            if parts.scheme != "https" or parts.hostname not in allowed:
                skipped.append(parts.hostname or uri)
                continue
            try:
                status, body = http(uri.rstrip("/") + "/timestamp/" + n.msg.hex(), None, HEADERS)
                if status != 200:
                    continue
                sub = _parse_reply(body, n.msg, depth + 1)
            except Exception:
                continue
            n.atts.remove(att)
            merge(n, sub)
            if any(k == "bitcoin" for k, _, _ in attestations(sub)):
                done += 1

    walk(root, 0)
    return (serialize(digest, root) if done else ots), done, skipped


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > (MAX_PROOF_BYTES * 4) // 3 + 8:
        raise OtsError("proof field too large")
    return base64.b64decode(s.encode("ascii"), validate=True)
