import json
from abc import ABC, abstractmethod
from urllib.request import urlopen

from fractal_tokens.services.generic import Service


class JwkService(Service, ABC):
    @abstractmethod
    def get_jwks(self, issuer: str):
        raise NotImplementedError


class LocalJwkService(JwkService):
    def __init__(self, jwks: list):
        self.jwks = jwks

    def get_jwks(self, issuer: str):
        return self.jwks


class RemoteJwkService(JwkService):
    def get_jwks(self, issuer: str):
        jsonurl = urlopen(f"{issuer}/public/keys")
        return json.loads(jsonurl.read())
