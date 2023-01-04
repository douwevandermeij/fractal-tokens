import json
from abc import ABC, abstractmethod
from dataclasses import dataclass

from fractal_tokens.services.generic import Service


@dataclass
class Jwk:
    id: str
    public_key: str


class JwkService(Service, ABC):
    @abstractmethod
    def get_jwks(self, issuer: str = "") -> list[Jwk]:
        raise NotImplementedError


class LocalJwkService(JwkService):
    def __init__(self, jwks: list[Jwk]):
        self.jwks = jwks

    def get_jwks(self, issuer: str = "") -> list[Jwk]:
        return self.jwks


class RemoteJwkService(JwkService):
    def get_jwks(self, issuer: str = "") -> list[Jwk]:
        from urllib.request import (  # needs to be here to be able to mock in tests
            urlopen,
        )

        jsonurl = urlopen(f"{issuer}/public/keys")
        return [Jwk(**k) for k in json.loads(jsonurl.read())]


class AutomaticJwkService(JwkService):
    def __init__(self, jwks: list[Jwk]):
        self.jwks = jwks

    def get_jwks(self, issuer: str = "") -> list[Jwk]:
        if issuer.startswith("http"):
            return RemoteJwkService().get_jwks(issuer)
        else:
            return LocalJwkService(self.jwks).get_jwks(issuer)
