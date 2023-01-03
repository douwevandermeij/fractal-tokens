from typing import Dict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwt

from fractal_tokens.exceptions import NotAllowedException
from fractal_tokens.services.jwk import JwkService
from fractal_tokens.services.jwt import JwtTokenService
from fractal_tokens.services.jwt.asymmetric import ExtendedAsymmetricJwtTokenService
from fractal_tokens.services.jwt.symmetric import SymmetricJwtTokenService
from fractal_tokens.settings import ACCESS_TOKEN_EXPIRATION_SECONDS


class AutomaticJwtTokenService(JwtTokenService):
    def __init__(self, issuer: str, secret: str, jwk_service: JwkService):
        self.issuer = issuer
        self.symmetric_token_service = SymmetricJwtTokenService(
            issuer=issuer,
            secret=secret,
        )
        self.jwk_service = jwk_service

    @classmethod
    def install(
        cls,
        app_name: str,
        app_env: str,
        app_domain: str,
        secret_key: str,
        jwk_service: JwkService,
    ):
        yield cls(
            f"{app_name}@{app_env}.{app_domain}",
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

    def verify(self, token: str, *, typ: str):
        headers = jwt.get_unverified_headers(token)
        claims = jwt.get_unverified_claims(token)
        if headers["alg"] == "HS256":
            return self.symmetric_token_service.verify(token, typ=typ)
        if headers["alg"] == "RS256":
            jwks = self.jwk_service.get_jwks(claims["iss"])
            for key in jwks:
                if key["id"] == headers["kid"]:
                    public_key = serialization.load_pem_public_key(
                        key["public_key"].encode("utf-8"), backend=default_backend()
                    )
                    asymmetric_token_service = ExtendedAsymmetricJwtTokenService(
                        issuer=self.issuer,
                        private_key="",
                        public_key=public_key,
                        kid=key["id"],
                    )
                    return asymmetric_token_service.verify(token, typ=typ)
        raise NotAllowedException("No permission!")

    def decode(self, token: str):
        ...

    def get_unverified_claims(self, token: str):
        return jwt.get_unverified_claims(token)
