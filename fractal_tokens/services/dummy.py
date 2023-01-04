import json

from fractal_tokens.exceptions import TokenInvalidException
from fractal_tokens.services.generic import TokenService
from fractal_tokens.settings import ACCESS_TOKEN_EXPIRATION_SECONDS


class DummyJsonTokenService(TokenService):
    def generate(
        self,
        payload: dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        return json.dumps(payload)

    def verify(self, token: str, *, typ: str = "access") -> dict:
        try:
            return self.decode(token)
        except Exception:
            raise TokenInvalidException()

    def decode(self, token: str):
        return json.loads(token)

    def get_unverified_claims(self, token: str):
        return self.decode(token)
