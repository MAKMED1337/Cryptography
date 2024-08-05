import os
import secrets
from dataclasses import dataclass
from hashlib import sha256
from math import gcd, lcm
from typing import override

from signature_algorithm import PrivateKey, PublicKey, SignatureAlgorithm

from .primes import random_prime


@dataclass
class RSAPrivateKey(PrivateKey):
    p: int
    q: int
    e: int

    @property
    def power(self) -> int:
        return lcm(self.p - 1, self.q - 1)

    @property
    def n(self) -> int:
        return self.p * self.q

    @property
    def d(self) -> int:
        return pow(self.e, -1, self.power)


@dataclass
class RSAPublicKey(PublicKey):
    n: int
    e: int


# https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
class RSA(SignatureAlgorithm):
    keyBits = 1024

    def _generate_e(self, power: int) -> int:
        e = 65357
        while gcd(e, power) != 1:
            e = secrets.randbelow(power - 1) + 1
        return e

    def _octet_len(self, n: int) -> int:
        return (n.bit_length() + 7) // 8

    @override
    def generate_key_pair(self) -> tuple[RSAPrivateKey, RSAPublicKey]:
        # keys are 1024 bits long, so modulo is 2048 bits long
        p = random_prime(1 << self.keyBits)
        q = random_prime(1 << self.keyBits)
        n = p * q
        power = lcm(p - 1, q - 1)  # lambda
        e = self._generate_e(power)
        return RSAPrivateKey(p, q, e), RSAPublicKey(n, e)

    # https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    def _I2OSP(self, x: int, xLen: int) -> bytes:
        # ignore the steps, because it is a builtin function in python
        return x.to_bytes(xLen, 'big')

    # https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
    def _OS2IP(self, X: bytes) -> int:
        # ignore the steps, because it is a builtin function in python
        return int.from_bytes(X, 'big')

    # https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1
    def _RSASP1(self, K: RSAPrivateKey, m: int) -> int:
        """
        1.  If the message representative m is not between 0 and n - 1,
            output "message representative out of range" and stop.
        """
        # ignore, this, because by modulo will be ok

        """
        2.  The signature representative s is computed as follows.
            a.  If the first form (n, d) of K is used, let s = m^d mod n.
        """
        # ignore the second case

        s = pow(m, K.d, K.n)

        """
        3.  Output s.
        """
        return s

    # https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.2
    def _RSAVP1(self, P: RSAPublicKey, s: int) -> int:
        """
        1.  If the signature representative s is not between 0 and n - 1,
            output "signature representative out of range" and stop.
        """
        # ignore, this, because by modulo will be ok

        """
        2.  Let m = s^e mod n.
        """
        m = pow(s, P.e, P.n)

        """
        3.  Output m.
        """
        return m

    # https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2.1
    def _MGF1(self, mgfSeed: bytes, maskLen: int) -> bytes:
        """
        1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
        """
        hLen = 256 // 8
        if maskLen > (1 << 32) * hLen:
            raise ValueError('mask too long')

        """
        2.  Let T be the empty octet string.
        """
        T = b''

        """
        3.  For counter from 0 to \\ceil (maskLen / hLen) - 1, do the
            following:
        """

        for counter in range((maskLen + hLen - 1) // hLen):
            """
            A.  Convert counter to an octet string C of length 4 octets (see
                Section 4.1):
                    C = I2OSP (counter, 4) .
            """
            C = self._I2OSP(counter, 4)

            """
            B.  Concatenate the hash of the seed mgfSeed and C to the octet
                string T:
                    T = T || Hash(mgfSeed || C) .
            """
            T = T + sha256(mgfSeed + C).digest()

        """
        4.  Output the leading maskLen octets of T as the octet string mask.
        """
        return T[:maskLen]

    # https://datatracker.ietf.org/doc/html/rfc8017#section-9.1.1
    def _EMSA_PSS_ENCODE(self, M: bytes, emBits: int, sLen: int) -> bytes:
        """
        1.   If the length of M is greater than the input limitation for
                   the hash function (2^61 - 1 octets for SHA-1), output
                   "message too long" and stop.
        """
        # Limit for SHA256
        if 8 * len(M) > (1 << 64) - 1:
            raise ValueError('message too long')

        """
        2.   Let mHash = Hash(M), an octet string of length hLen.
        """
        mHash = sha256(M).digest()
        hLen = len(mHash)

        """
        3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
        """
        emLen = (emBits + 7) // 8
        if emLen < hLen + sLen + 2:
            raise ValueError('encoding error')

        """
        4.   Generate a random octet string salt of length sLen; if sLen =
             0, then salt is the empty string.
        """
        salt = os.urandom(sLen)

        """
        5.   Let
               M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
             M' is an octet string of length 8 + hLen + sLen with eight
             initial zero octets.
        """
        M_ = b'\x00' * 8 + mHash + salt

        """
        6.   Let H = Hash(M'), an octet string of length hLen.
        """
        H = sha256(M_).digest()
        hLen = len(H)

        """
        7.   Generate an octet string PS consisting of emLen - sLen - hLen
             - 2 zero octets.  The length of PS may be 0.
        """
        PS = b'\x00' * (emLen - sLen - hLen - 2)

        """
        8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
             emLen - hLen - 1.
        """
        DB = PS + b'\x01' + salt

        """
        9.   Let dbMask = MGF(H, emLen - hLen - 1).
        """
        dbMask = self._MGF1(H, emLen - hLen - 1)

        """
        10.  Let maskedDB = DB \\xor dbMask.
        """
        maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask, strict=True))

        """
        11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
             in maskedDB to zero.
        """
        bitsCount = 8 * emLen - emBits
        # bits are in reverse order, so we can "overflow"
        value = ((maskedDB[0] << bitsCount) & 255) >> bitsCount
        maskedDB = bytes([(value)]) + maskedDB[1:]

        """
        12.  Let EM = maskedDB || H || 0xbc.
        """
        EM = maskedDB + H + b'\xbc'

        """
        13.  Output EM.
        """
        return EM

    # https://datatracker.ietf.org/doc/html/rfc8017#section-9.1.2
    def _EMSA_PSS_VERIFY(self, M: bytes, EM: bytes, emBits: int, sLen: int) -> bool:
        """
        1.  If the length of M is greater than the input limitation for
            the hash function (2^61 - 1 octets for SHA-1), output
            "inconsistent" and stop.
        """
        # Limit for SHA256
        if 8 * len(M) > (1 << 64) - 1:
            raise ValueError('message too long')

        """
        2.  Let mHash = Hash(M), an octet string of length hLen.
        """
        mHash = sha256(M).digest()
        hLen = len(mHash)

        """
        3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
        """
        emLen = len(EM)
        if emLen < hLen + sLen + 2:
            return False

        """
        4.  If the rightmost octet of EM does not have hexadecimal value
            0xbc, output "inconsistent" and stop.
        """
        if EM[-1] != 0xBC:  # noqa: PLR2004
            return False

        """
        5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
            and let H be the next hLen octets.
        """
        length = emLen - hLen - 1
        maskedDB = EM[:length]
        H = EM[length : length + hLen]

        """
        6.  If the leftmost 8emLen - emBits bits of the leftmost octet in
            maskedDB are not all equal to zero, output "inconsistent" and
            stop.
        """
        bitsCount = 8 * emLen - emBits
        # bits are in reverse order, so we can check for an overflow
        if (maskedDB[0] << bitsCount) >> 8:
            return False

        """
        7.  Let dbMask = MGF(H, emLen - hLen - 1).
        """
        dbMask = self._MGF1(H, emLen - hLen - 1)

        """
        8. Let DB = maskedDB \\xor dbMask.
        """
        DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask, strict=True))

        """
        9.  Set the leftmost 8emLen - emBits bits of the leftmost octet
            in DB to zero.
        """
        bitsCount = 8 * emLen - emBits
        # bits are in reverse order, so we can "overflow"
        value = ((DB[0] << bitsCount) & 255) >> bitsCount
        DB = bytes([value]) + DB[1:]

        """
        10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not
            zero or if the octet at position emLen - hLen - sLen - 1 (the
            leftmost position is "position 1") does not have hexadecimal
            value 0x01, output "inconsistent" and stop.
        """
        length = emLen - hLen - sLen - 2
        if DB[:length] != b'\x00' * length or DB[length] != 0x01:
            return False

        """
        11.  Let salt be the last sLen octets of DB.
        """
        salt = DB[len(DB) - sLen :]

        """
        12. Let
                M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            M' is an octet string of length 8 + hLen + sLen with eight
            initial zero octets.
        """
        M_ = b'\x00' * 8 + mHash + salt

        """
        13.  Let H' = Hash(M'), an octet string of length hLen.
        """
        H_ = sha256(M_).digest()

        """
        14. If H = H', output "consistent".  Otherwise, output
            "inconsistent".
        """
        return H == H_

    # https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
    def _RSASSA_PSS(self, K: RSAPrivateKey, M: bytes, sLen: int) -> bytes:
        """
        1.  EMSA-PSS encoding: Apply the EMSA-PSS encoding operation
            (Section 9.1.1) to the message M to produce an encoded message
            EM of length \\ceil ((modBits - 1)/8) octets such that the bit
            length of the integer OS2IP (EM) (see Section 4.2) is at most
            modBits - 1, where modBits is the length in bits of the RSA
            modulus n:
                EM = EMSA-PSS-ENCODE (M, modBits - 1).
            Note that the octet length of EM will be one less than k if
            modBits - 1 is divisible by 8 and equal to k otherwise.  If
            the encoding operation outputs "message too long", output
            "message too long" and stop.  If the encoding operation
            outputs "encoding error", output "encoding error" and stop.
        """
        modBits = K.n.bit_length()
        EM = self._EMSA_PSS_ENCODE(M, modBits - 1, sLen)

        """
        2.  RSA signature:
            a.  Convert the encoded message EM to an integer message
                representative m (see Section 4.2):
                    m = OS2IP (EM).
            b.  Apply the RSASP1 signature primitive (Section 5.2.1) to
                the RSA private key K and the message representative m to
                produce an integer signature representative s:
                    s = RSASP1 (K, m).
            c.  Convert the signature representative s to a signature S of
                length k octets (see Section 4.1):
                    S = I2OSP (s, k).
        """
        m = self._OS2IP(EM)
        s = self._RSASP1(K, m)
        k = self._octet_len(K.n)
        S = self._I2OSP(s, k)

        """
        3.  Output the signature S.
        """
        return S

    # https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    def _RSASSA_PSS_VERIFY(self, P: RSAPublicKey, M: bytes, S: bytes, sLen: int) -> bool:
        """
        1.  Length checking: If the length of the signature S is not k
            octets, output "invalid signature" and stop.
        """
        if len(S) != self._octet_len(P.n):
            # do not raise, simply return
            return False

        """
        2.  RSA verification:
          a.  Convert the signature S to an integer signature
              representative s (see Section 4.2):
                 s = OS2IP (S).
          b.  Apply the RSAVP1 verification primitive (Section 5.2.2) to
              the RSA public key (n, e) and the signature representative
              s to produce an integer message representative m:
                 m = RSAVP1 ((n, e), s).
              If RSAVP1 output "signature representative out of range",
              output "invalid signature" and stop.
          c.  Convert the message representative m to an encoded message
              EM of length emLen = \\ceil ((modBits - 1)/8) octets, where
              modBits is the length in bits of the RSA modulus n (see
              Section 4.1):
                 EM = I2OSP (m, emLen).
              Note that emLen will be one less than k if modBits - 1 is
              divisible by 8 and equal to k otherwise.  If I2OSP outputs
              "integer too large", output "invalid signature" and stop.
        """
        s = self._OS2IP(S)
        m = self._RSAVP1(P, s)
        modBits = P.n.bit_length()
        emLen = (modBits + 6) // 8  # use floor instead of ceil: -1 + 7 = +6
        EM = self._I2OSP(m, emLen)

        """
        3.  EMSA-PSS verification: Apply the EMSA-PSS verification
            operation (Section 9.1.2) to the message M and the encoded
            message EM to determine whether they are consistent:
                Result = EMSA-PSS-VERIFY (M, EM, modBits - 1).
        """
        Result = self._EMSA_PSS_VERIFY(M, EM, modBits - 1, sLen)

        """
        4.  If Result = "consistent", output "valid signature".
            Otherwise, output "invalid signature".
        """
        # because we are using bool instead of string, we can simply return
        return Result

    @override
    def sign_message(self, message: bytes, private_key: PrivateKey, sLen: int = 0) -> bytes:
        if not isinstance(private_key, RSAPrivateKey):
            msg = f'Excepted RSAPrivateKey, but got: {type(private_key)}'
            raise TypeError(msg)
        return self._RSASSA_PSS(private_key, message, sLen)

    @override
    def verify_signature(self, message: bytes, public_key: PublicKey, signature: bytes, sLen: int = 0) -> bool:
        if not isinstance(public_key, RSAPublicKey):
            msg = f'Excepted RSAPublicKey, but got: {type(public_key)}'
            raise TypeError(msg)
        return self._RSASSA_PSS_VERIFY(public_key, message, signature, sLen)
