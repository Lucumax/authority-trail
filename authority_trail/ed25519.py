"""Ed25519 (RFC 8032) in pure Python, standard library only.

Adapted from the Python reference code in RFC 8032, section 6 (code components of RFCs are
available under the Revised BSD licence, see NOTICE). Additions: public-key admission checks
that refuse small-order points, and stricter input handling.

verify() is what makes the verifier dependency-free: an auditor needs only the Python
standard library. sign() is the RFC reference algorithm. It is NOT constant time. keys.py
prefers the `cryptography` package for signing when it is installed; tests check both agree.
"""
from __future__ import annotations

import hashlib

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


_d = -121665 * _inv(121666) % p
_sqrt_m1 = pow(2, (p - 1) // 4, p)


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * _inv(5) % p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * _d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _compress(P) -> bytes:
    zinv = _inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _modq(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % q


def _expand(seed: bytes):
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _compress(_mul(a, _G))
    r = _modq(prefix + msg)
    Rs = _compress(_mul(r, _G))
    h = _modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


_IDENTITY = (0, 1, 1, 0)


def is_small_order(P) -> bool:
    """True if 8*P is the identity: P lies in the small torsion subgroup (includes the identity)."""
    return _equal(_mul(8, P), _IDENTITY)


def is_valid_public(public: bytes) -> bool:
    """A public key this project accepts: canonical 32-byte point encoding, on the curve, not of small order."""
    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        return False
    A = _decompress(bytes(public))
    return A is not None and not is_small_order(A)


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    if A is None or is_small_order(A):
        return False
    Rs = signature[:32]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = _modq(Rs + public + msg)
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))
