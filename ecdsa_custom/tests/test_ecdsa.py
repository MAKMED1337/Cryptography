from hashlib import sha256

import pytest
from ecdsa import BadSignatureError, MalformedPointError, SECP256k1, SigningKey

from signature_algorithm import PrivateKey, PublicKey

from ..ecdsa import ECDSA, ECPrivateKey, ECPublicKey
from ..elliptic_curve import PointAtInfinity, secp256k1


def test_key_types() -> None:
    ecdsa = ECDSA(secp256k1)
    with pytest.raises(TypeError):
        ecdsa.sign_message(b'', PrivateKey())
    with pytest.raises(TypeError):
        ecdsa.verify_signature(b'', PublicKey(), b'')


def test_custom_ecdsa() -> None:
    ecdsa = ECDSA(secp256k1)
    sk, pk = ecdsa.generate_key_pair()

    message = b'test message'

    signature = ecdsa.sign_message(message, sk)
    assert ecdsa.verify_signature(message, pk, signature)
    assert not ecdsa.verify_signature(message, pk, b'')  # dummy

    message2 = b'test message2'
    signature2 = ecdsa.sign_message(message2, sk)
    assert not ecdsa.verify_signature(message, pk, signature2)  # different message

    sk2, _ = ecdsa.generate_key_pair()
    signature3 = ecdsa.sign_message(message, sk2)
    assert not ecdsa.verify_signature(message, pk, signature3)  # different private key


def test_with_library() -> None:
    ecdsa = ECDSA(secp256k1)
    message = b'test message'

    lib_sk = SigningKey.generate(SECP256k1, hashfunc=sha256)
    lib_pk = lib_sk.get_verifying_key()
    assert lib_sk.privkey is not None
    assert lib_pk is not None

    sk = ECPrivateKey(lib_sk.privkey.secret_multiplier)
    point = secp256k1.multiply(secp256k1.G, sk.k)
    assert not isinstance(point, PointAtInfinity)

    negative = point.y == secp256k1.get_y(point.x, negative=True)  # Probable something better exists
    pk = ECPublicKey(point.x, negative)

    def sigencode(r: int, s: int, order: int) -> bytes:
        length = (order.bit_length() + 7) // 8
        return int.to_bytes(r, length) + int.to_bytes(s, length)

    def sigdecode(signature: bytes, order: int) -> tuple[int, int]:
        length = (order.bit_length() + 7) // 8
        if len(signature) != 2 * length:
            raise MalformedPointError
        return int.from_bytes(signature[:length]), int.from_bytes(signature[length:])

    # Verify signature
    signature = lib_sk.sign(message, sigencode=sigencode)
    assert ecdsa.verify_signature(message, pk, signature)

    my_signature = ecdsa.sign_message(message, sk)
    assert lib_pk.verify(my_signature, message, sigdecode=sigdecode)

    # Do not verify wrong signature
    message2 = b'test message2'
    signature2 = lib_sk.sign(message2, hashfunc=sha256, sigencode=sigencode)
    assert not ecdsa.verify_signature(message, pk, signature2)

    my_signature2 = ecdsa.sign_message(message2, sk)
    with pytest.raises(BadSignatureError):
        lib_pk.verify(my_signature2, message, sigdecode=sigdecode)
