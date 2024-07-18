class PrivateKey:
    pass


class PublicKey:
    pass


class SignatureAlgorithm:
    def generate_key_pair(self) -> tuple[PrivateKey, PublicKey]:
        raise NotImplementedError

    def sign_message(self, message: bytes) -> bytes:
        raise NotImplementedError

    def verify_signature(self, message: bytes, public_key: PublicKey, signature: bytes) -> bool:
        raise NotImplementedError
