
import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA as RSA_LIB
from Crypto.Signature import pss

from signature_algorithm import PrivateKey, PublicKey

from ..rsa import RSA, RSAPrivateKey, RSAPublicKey


def test_key_types() -> None:
    rsa = RSA()
    with pytest.raises(TypeError):
        rsa.sign_message(b'', PrivateKey())
    with pytest.raises(TypeError):
        rsa.verify_signature(b'', PublicKey(), b'')


def test_custom_rsa() -> None:
    rsa = RSA()

    sk, pk = rsa.generate_key_pair()
    message = b'test message'

    signature = rsa.sign_message(message, sk)
    assert rsa.verify_signature(message, pk, signature)
    assert not rsa.verify_signature(message, pk, b'')  # dummy

    message2 = b'test message2'
    signature2 = rsa.sign_message(message2, sk)
    assert not rsa.verify_signature(message, pk, signature2)  # different message

    sk2, _ = rsa.generate_key_pair()
    signature3 = rsa.sign_message(message, sk2)
    assert not rsa.verify_signature(message, pk, signature3)  # different private key


def test_rsa_with_library_custom_key() -> None:
    message = b'test message'

    rsa = RSA()
    sk, pk = rsa.generate_key_pair()
    sign = rsa.sign_message(message, sk)

    key = RSA_LIB.construct((pk.n, pk.e, sk.d, sk.p, sk.q), consistency_check=True)
    h = SHA256.new(message)
    sign_lib = pss.new(key, salt_bytes=0).sign(h)

    assert sign == sign_lib

def test_rsa_with_library_library_key() -> None:
    message = b'test message'

    rsa = RSA()
    key = RSA_LIB.generate(rsa.keyBits)

    sk = RSAPrivateKey(key.p, key.q, key.e)
    pk = RSAPublicKey(key.n, key.e)

    sign = rsa.sign_message(message, sk)

    h = SHA256.new(message)
    sign_lib = pss.new(key, salt_bytes=0).sign(h)

    assert sign == sign_lib
    assert rsa.verify_signature(message, pk, sign)
