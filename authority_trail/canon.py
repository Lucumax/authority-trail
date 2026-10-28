"""Canonical JSON: the one byte form that is hashed and signed.

Rules: object keys sorted, no whitespace, UTF-8, integers only (floats are refused so two
implementations can never disagree on number formatting). A second implementation only needs
to follow these four rules to produce identical bytes.
"""
from __future__ import annotations

import hashlib
import json


MAX_SAFE_INT = 2**53 - 1


class CanonError(ValueError):
    pass


def _check(obj, path="$"):
    if obj is None or isinstance(obj, (str, bool)):
        return
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INT:
            raise CanonError(f"integer too large at {path}; limit is 2^53-1 so JavaScript and Python agree")
        return
    if isinstance(obj, float):
        raise CanonError(f"float not allowed at {path}; use integer minor units")
    if isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check(v, f"{path}[{i}]")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonError(f"non-string key at {path}")
            _check(v, f"{path}.{k}")
        return
    raise CanonError(f"type {type(obj).__name__} not allowed at {path}")


def canonical(obj) -> bytes:
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj) -> str:
    return sha256_hex(canonical(obj))
