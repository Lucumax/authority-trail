"""Key handling. A Party holds an Ed25519 seed (private) and exposes the public key and key id."""
from __future__ import annotations

import hashlib
import os

from . import ed25519

try:  # optional: faster, constant-time signing
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:  # pragma: no cover
    Ed25519PrivateKey = None


def key_id(public_hex: str) -> str:
    """Short fingerprint: first 32 hex chars of SHA-256 of the raw public key."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]


def fingerprint(public_hex: str) -> str:
    k = key_id(public_hex)
    return " ".join(k[i:i + 4] for i in range(0, len(k), 4))


def sign_bytes(seed: bytes, msg: bytes) -> bytes:
    if Ed25519PrivateKey is not None:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    return ed25519.sign(seed, msg)


class Party:
    """A named signer. In real use the seed lives in a key store or HSM; here it is a file or memory."""

    def __init__(self, name: str, seed: bytes | None = None):
        self.name = name
        self.seed = seed if seed is not None else os.urandom(32)
        if len(self.seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.public_hex = ed25519.public_from_seed(self.seed).hex()
        self.key_id = key_id(self.public_hex)

    def sign(self, msg: bytes) -> bytes:
        return sign_bytes(self.seed, msg)

    def ref(self) -> dict:
        return {"name": self.name, "key": self.public_hex}

    def save_seed(self, path: str) -> None:
        """Write the private seed to a NEW file, readable by the owner only (POSIX mode 0600).
        Refuses to overwrite. On Windows the mode bits have little effect: keep the file in a
        protected folder. Never commit it."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(self.seed.hex() + "\n")

    @classmethod
    def load(cls, name: str, path: str) -> "Party":
        with open(path, encoding="utf-8") as f:
            return cls(name, bytes.fromhex(f.read().strip()))
