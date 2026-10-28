import os

import pytest

from authority_trail import ed25519
from authority_trail.canon import CanonError, canonical, digest
from authority_trail.keys import Party, key_id

# RFC 8032 section 7.1 test vectors
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("seed,pub,msg,sig", VECTORS)
def test_rfc8032_vectors(seed, pub, msg, sig):
    seed, pub, msg, sig = (bytes.fromhex(x) for x in (seed, pub, msg, sig))
    assert ed25519.public_from_seed(seed) == pub
    assert ed25519.sign(seed, msg) == sig
    assert ed25519.verify(pub, msg, sig)
    assert not ed25519.verify(pub, msg + b"x", sig)
    bad = bytearray(sig)
    bad[10] ^= 1
    assert not ed25519.verify(pub, msg, bytes(bad))


def test_reference_agrees_with_cryptography_library():
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    for _ in range(5):
        seed = os.urandom(32)
        msg = os.urandom(50)
        k = crypto.Ed25519PrivateKey.from_private_bytes(seed)
        sig = k.sign(msg)
        pub = k.public_key().public_bytes_raw()
        assert ed25519.public_from_seed(seed) == pub
        assert ed25519.sign(seed, msg) == sig
        assert ed25519.verify(pub, msg, sig)


def test_verify_rejects_malformed_inputs():
    seed = os.urandom(32)
    pub = ed25519.public_from_seed(seed)
    sig = ed25519.sign(seed, b"m")
    assert not ed25519.verify(pub[:31], b"m", sig)
    assert not ed25519.verify(pub, b"m", sig[:63])
    s_big = sig[:32] + (ed25519.q + 1).to_bytes(32, "little")  # non-canonical s
    assert not ed25519.verify(pub, b"m", s_big)
    assert not ed25519.verify(b"\xff" * 32, b"m", sig)


def test_canonical_json_rules():
    assert canonical({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode("utf-8")
    assert digest({"a": 1}) == digest({"a": 1})
    for bad in ({"x": 1.5}, {"x": {1: 2}}, {"x": {1, 2}}, {"x": b"b"}):
        with pytest.raises(CanonError):
            canonical(bad)


def test_party_key_id_is_stable_and_distinct():
    a, b = Party("a"), Party("b")
    assert a.key_id == key_id(a.public_hex) and a.key_id != b.key_id and len(a.key_id) == 32


def test_canonical_rejects_integers_javascript_cannot_hold():
    assert canonical({"x": 2**53 - 1})
    with pytest.raises(CanonError):
        canonical({"x": 2**53})
    with pytest.raises(CanonError):
        canonical({"x": -(2**53)})
