from abc import ABC, abstractmethod

from jose import ExpiredSignatureError, JWTError

from fractal_tokens.exceptions import TokenExpiredException, TokenInvalidException
from fractal_tokens.services.generic import TokenService


class JwtTokenService(TokenService, ABC):
    @abstractmethod
    def decode(self, token: str):
        raise NotImplementedError

    def verify(self, token: str, *, typ: str):
        try:
            payload = self.decode(token)
        except ExpiredSignatureError:
            raise TokenExpiredException()
        except JWTError:
            raise TokenInvalidException()
        if payload["typ"] != typ:
            raise TokenInvalidException()
        return payload
