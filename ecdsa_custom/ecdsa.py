import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import override

from signature_algorithm import PrivateKey, PublicKey, SignatureAlgorithm

from .elliptic_curve import EllipticCurve, NormalPoint, PointAtInfinity


@dataclass
class ECPrivateKey(PrivateKey):
    k: int


@dataclass
class ECPublicKey(PublicKey):
    x: int
    negative: bool


class ECDSA(SignatureAlgorithm):
    curve: EllipticCurve

    def __init__(self, curve: EllipticCurve):
        self.curve = curve

    @override
    def generate_key_pair(self) -> tuple[ECPrivateKey, ECPublicKey]:
        k = 1 + secrets.randbelow(self.curve.n - 2)
        point = self.curve.multiply(self.curve.G, k)
        assert isinstance(point, NormalPoint)  # noqa: S101

        negative = point.y == self.curve.get_y(point.x, negative=True)  # Probable something better exists
        return ECPrivateKey(k), ECPublicKey(point.x, negative)

    @override
    # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm
    def sign_message(self, message: bytes, private_key: PrivateKey) -> bytes:
        if not isinstance(private_key, ECPrivateKey):
            msg = f'Excepted ECPrivateKey, but got: {type(private_key)}'
            raise TypeError(msg)

        # 1. Calculate e = HASH(m). (Here HASH is a cryptographic hash function, such as SHA-2, with the output converted to an integer.)
        e = int.from_bytes(sha256(message).digest())

        # 2. Let z be the L_n leftmost bits of e, where L_n is the bit length of the group order n. (Note that z can be greater than n but not longer)
        l_n = self.curve.n.bit_length()
        z = e & ((1 << l_n) - 1)

        # loop, because of coming back to the third step
        while True:
            # 3. Select a cryptographically secure random integer k from [1, n - 1].
            k = 1 + secrets.randbelow(self.curve.n - 2)

            # 4. Calculate the curve point (x1, y1) = k * G.
            point = self.curve.multiply(self.curve.G, k)
            assert isinstance(point, NormalPoint)  # noqa: S101

            # 5. Calculate r = x1 mod n. If r = 0, go back to step 3.
            r = point.x % self.curve.n
            if r == 0:
                continue

            # 6. Calculate s = k^{-1} (z + r d_A) mod n. If s = 0, go back to step 3.
            s = pow(k, -1, self.curve.n) * (z + r * private_key.k) % self.curve.n
            if s == 0:
                continue

            # 7. The signature is the pair (r, s). (And (r , -s mod n) is also a valid signature.)
            # we need encode it using bytes, so lets align to the length of n

            # internal format for a signature
            length = (self.curve.n.bit_length() + 7) // 8
            return int.to_bytes(r, length) + int.to_bytes(s, length)

    @override
    # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_verification_algorithm
    def verify_signature(self, message: bytes, public_key: PublicKey, signature: bytes) -> bool:
        if not isinstance(public_key, ECPublicKey):
            msg = f'Excepted ECPublicKey, but got: {type(public_key)}'
            raise TypeError(msg)

        # internal format for a signature
        length = (self.curve.n.bit_length() + 7) // 8
        if len(signature) != 2 * length:
            return False

        r, s = int.from_bytes(signature[:length]), int.from_bytes(signature[length:])

        # 1. Check that Q_A is not equal to the identity element O, and its coordinates are otherwise valid.
        # 2. Check that Q_A lies on the curve.
        # Combined 1, 2
        try:
            x = public_key.x
            Q = NormalPoint(x, self.curve.get_y(x, negative=public_key.negative))  # noqa: N806
        except ValueError:
            return False

        # Check that n * Q_A = O.
        if not isinstance(self.curve.multiply(Q, self.curve.n), PointAtInfinity):
            return False

        # 1. Verify that r and s are integers in [1, n - 1]. If not, the signature is invalid.
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False

        # 2. Calculate e = HASH (m), where HASH is the same function used in the signature generation.
        e = int.from_bytes(sha256(message).digest())

        # 3. Let z be the L_n leftmost bits of e.
        l_n = self.curve.n.bit_length()
        z = e & ((1 << l_n) - 1)

        # 4. Calculate u_1 = z * s^{-1} mod n and u_2 = r * s^{-1} mod n.
        u1 = z * pow(s, -1, self.curve.n) % self.curve.n
        u2 = r * pow(s, -1, self.curve.n) % self.curve.n

        # 5. Calculate the curve point (x1, y1) = u_1 * G + u_2 * Q_A. If (x1, y1) = O then the signature is invalid.
        point = self.curve.add(self.curve.multiply(self.curve.G, u1), self.curve.multiply(Q, u2))
        if isinstance(point, PointAtInfinity):
            return False

        # 6. The signature is valid if r = x1 (mod n), invalid otherwise.
        return (r - point.x) % self.curve.n == 0
