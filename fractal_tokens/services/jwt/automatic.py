from typing import Dict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwt

from fractal_tokens.exceptions import NotAllowedException
from fractal_tokens.services.jwk import JwkService
from fractal_tokens.services.jwt import JwtTokenService
from fractal_tokens.services.jwt.asymmetric import AsymmetricJwtTokenService
from fractal_tokens.services.jwt.symmetric import SymmetricJwtTokenService
from fractal_tokens.settings import ACCESS_TOKEN_EXPIRATION_SECONDS


class AutomaticJwtTokenService(JwtTokenService):
    def __init__(
        self, issuer: str, secret_key: str, jwk_service: JwkService, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.issuer = issuer
        self.symmetric_token_service = SymmetricJwtTokenService(
            issuer=issuer,
            secret_key=secret_key,
        )
        self.jwk_service = jwk_service

    @classmethod
    def install(
        cls,
        issuer: str,
        secret_key: str,
        jwk_service: JwkService,
    ):
        yield cls(
            issuer,
            secret_key,
            jwk_service,
        )

    def generate(
        self,
        payload: Dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        return self.symmetric_token_service.generate(payload, token_type, seconds_valid)

    def decode(self, token: str) -> dict:
        headers = jwt.get_unverified_headers(token)
        claims = jwt.get_unverified_claims(token)
        if headers["alg"] == "HS256":
            return self.symmetric_token_service.decode(token)
        if headers["alg"] == "RS256":
            jwks = self.jwk_service.get_jwks(claims["iss"])
            kid = headers.get("kid", None)
            for key in jwks:
                if key.id == kid or not kid:
                    public_key = serialization.load_pem_public_key(
                        key.public_key.encode("utf-8"), backend=default_backend()
                    )
                    asymmetric_token_service = AsymmetricJwtTokenService(
                        issuer=self.issuer,
                        private_key="",
                        public_key=public_key,
                    )
                    return asymmetric_token_service.decode(token)
        raise NotAllowedException("No permission!")

    def get_unverified_claims(self, token: str) -> dict:
        return jwt.get_unverified_claims(token)
