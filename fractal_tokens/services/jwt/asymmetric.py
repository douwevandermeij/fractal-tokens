from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PUBLIC_KEY_TYPES
from jose import jwt

from fractal_tokens.services.jwt import JwtTokenService
from fractal_tokens.settings import ACCESS_TOKEN_EXPIRATION_SECONDS


class AsymmetricJwtTokenService(JwtTokenService):
    def __init__(
        self,
        issuer: str,
        private_key: str,
        public_key: PUBLIC_KEY_TYPES,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.issuer = issuer
        self.private_key = private_key
        self.public_key = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        self.algorithm = "RS256"

    @classmethod
    def install(cls, *args, **kwargs):
        yield cls(*args, **kwargs)

    def generate(
        self,
        payload: dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        return jwt.encode(
            self._prepare(payload, token_type, seconds_valid, self.issuer),
            self.private_key,
            algorithm=self.algorithm,
        )

    def decode(self, token: str) -> dict:
        return jwt.decode(
            token,
            self.public_key,
            algorithms=self.algorithm,
            issuer=self.issuer,
        )

    def get_unverified_claims(self, token: str) -> dict:
        return jwt.get_unverified_claims(token)


class ExtendedAsymmetricJwtTokenService(AsymmetricJwtTokenService):
    def __init__(
        self,
        issuer: str,
        private_key: str,
        public_key: PUBLIC_KEY_TYPES,
        kid: str,
        *args,
        **kwargs,
    ):
        super(ExtendedAsymmetricJwtTokenService, self).__init__(
            issuer, private_key, public_key, *args, **kwargs
        )
        self.kid = kid

    @classmethod
    def install(
        cls,
        issuer: str,
        private_key: str,
        public_key: PUBLIC_KEY_TYPES,
        kid: str,
    ):
        yield cls(
            issuer,
            private_key,
            public_key,
            kid,
        )

    def generate(
        self,
        payload: dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        return jwt.encode(
            self._prepare(payload, token_type, seconds_valid, self.issuer),
            self.private_key,
            algorithm=self.algorithm,
            headers={"kid": self.kid},
        )
