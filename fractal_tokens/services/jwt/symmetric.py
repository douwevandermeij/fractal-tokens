from typing import Dict

from jose import jwt

from fractal_tokens.services.jwt import JwtTokenService
from fractal_tokens.settings import ACCESS_TOKEN_EXPIRATION_SECONDS


class SymmetricJwtTokenService(JwtTokenService):
    def __init__(self, issuer: str, secret: str):
        self.issuer = issuer
        self.secret = secret
        self.algorithm = "HS256"

    @classmethod
    def install(cls, app_name: str, app_env: str, app_domain: str, secret_key: str):
        yield cls(
            f"{app_name}@{app_env}.{app_domain}",
            secret_key,
        )

    def generate(
        self,
        payload: Dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        return jwt.encode(
            self._prepare(payload, token_type, seconds_valid, self.issuer),
            self.secret,
            algorithm=self.algorithm,
        )

    def decode(self, token: str):
        return jwt.decode(token, self.secret, algorithms=self.algorithm)

    def get_unverified_claims(self, token: str):
        return jwt.get_unverified_claims(token)
