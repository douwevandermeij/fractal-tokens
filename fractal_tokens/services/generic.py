import uuid
from abc import ABC, abstractmethod
from calendar import timegm
from datetime import datetime
from typing import Dict

from fractal_tokens.settings import (
    ACCESS_TOKEN_EXPIRATION_SECONDS,
    REFRESH_TOKEN_EXPIRATION_SECONDS,
)


class Service(
    ABC
):  # TODO copied from fractal-toolkit until services are extracted to separate package
    @classmethod
    def install(cls, *args, **kwargs):
        yield cls()

    def is_healthy(self) -> bool:
        return True


class TokenService(Service):
    @abstractmethod
    def generate(
        self,
        payload: Dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        raise NotImplementedError

    def _prepare(
        self, payload: Dict, token_type: str, seconds_valid: int, issuer: str
    ) -> Dict:
        utcnow = timegm(datetime.utcnow().utctimetuple())
        if not seconds_valid:
            seconds_valid = (
                REFRESH_TOKEN_EXPIRATION_SECONDS
                if token_type == "refresh"
                else ACCESS_TOKEN_EXPIRATION_SECONDS
            )
        payload.update(
            {
                "iat": utcnow,
                "nbf": utcnow,
                "jti": str(uuid.uuid4()),
                "iss": issuer,
                "exp": utcnow + seconds_valid,
                "typ": token_type,
            }
        )
        return payload

    @abstractmethod
    def verify(self, token: str, *, typ: str = "access") -> dict:
        raise NotImplementedError

    @abstractmethod
    def decode(self, token: str):
        raise NotImplementedError

    @abstractmethod
    def get_unverified_claims(self, token: str):
        raise NotImplementedError
