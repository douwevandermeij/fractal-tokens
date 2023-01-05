# Fractal Tokens

> Fractal Tokens provides a flexible way to generate and verify JWT tokens for your Python applications.

[![PyPI Version][pypi-image]][pypi-url]
[![Build Status][build-image]][build-url]
[![Code Coverage][coverage-image]][coverage-url]
[![Code Quality][quality-image]][quality-url]

<!-- Badges -->

[pypi-image]: https://img.shields.io/pypi/v/fractal-tokens
[pypi-url]: https://pypi.org/project/fractal-tokens/
[build-image]: https://github.com/douwevandermeij/fractal-tokens/actions/workflows/build.yml/badge.svg
[build-url]: https://github.com/douwevandermeij/fractal-tokens/actions/workflows/build.yml
[coverage-image]: https://codecov.io/gh/douwevandermeij/fractal-tokens/branch/main/graph/badge.svg
[coverage-url]: https://codecov.io/gh/douwevandermeij/fractal-tokens
[quality-image]: https://api.codeclimate.com/v1/badges/9242f796b5edee2c327d/maintainability
[quality-url]: https://codeclimate.com/github/douwevandermeij/fractal-tokens

## Installation

```sh
pip install fractal-tokens
```

## Development

Setup the development environment by running:

```sh
make deps
pre-commit install
```

Happy coding.

Occasionally you can run:

```sh
make lint
```

This is not explicitly necessary because the git hook does the same thing.

**Do not disable the git hooks upon commit!**

## Usage

A token is a digital key that gives (temporary) access to a certain (online) resource.
This can be anything, it can give a user access to a backend system (login/authentication), or allow a certain file to be downloaded, etc.

In any case, the token is stand-alone, contains its own permissions, is signed and can (thus) be validated and used in a stateless way.
Only to be able to validate the signature, a key related to the key that has been used to sign the token, is necessary to the validating service (the validator).

In case of a symmetric encryption key, the exact same "secret key" needs to be available to the validator.\
In case of an asymmetric encryption key (public/private key pair), the public key needs to be available to the validator (assuming the token has been signed with the private key).

### Dummy TokenService

To illustrate how the token service works we'll be using a dummy TokenService. This dummy TokenService doesn't use encryption.
In our case, it uses JSON to generate and verify tokens (json.dumps and json.loads respectively).

Consider the following TokenService:

```python
class DummyJsonTokenService(TokenService):
    def __init__(self, token_payload_cls: Type[TokenPayload] = TokenPayload):
        self.token_payload_cls = token_payload_cls

    def generate(
        self,
        payload: dict,
        token_type: str = "access",
        seconds_valid: int = ACCESS_TOKEN_EXPIRATION_SECONDS,
    ) -> str:
        return json.dumps(self._prepare(payload, token_type, seconds_valid, "dummy"))

    def verify(self, token: str, *, typ: str = "access") -> TokenPayload:
        try:
            return self.token_payload_cls(**self.decode(token))
        except Exception:
            raise TokenInvalidException()

    def decode(self, token: str) -> dict:
        return json.loads(token)

    def get_unverified_claims(self, token: str) -> dict:
        return self.decode(token)
```

Note the `generate` function calls `json.dumps` and the `decode` function, which is also called from `verify`, will call `json.loads`.

The generated tokens from this TokenService are in a JSON format. The JSON formatted tokens can be verified and a TokenPayload object will be returned.

This TokenService can be used during testing. The generated tokens are human-readable, so easy to debug.

Notice the `verify` function returns a TokenPayload object.

### TokenPayload

The `verify` function of a TokenService returns a TokenPayload object, or a subclass. To use a subclass, that class needs to be registered upon initialization of the TokenService.

The TokenPayload is a contract about the payload of the token.

While generating and verifying tokens is stateless, it can be handy to make agreements about the payload structure of the tokens.
Stateless token authentication can be particularly handy in a microservice architecture, where one microservice generated the token
and another consuming (validating) it to be able to process something on behalf of the token's subject.
Since both microservices have their own application context, they don't share the same code (directly).
This means that the payload that is used to generate the token, may be of a different structure than the payload that is expected in the consuming service.
This may happen when one of the two microservices gets a change regarding the payload structure and the other doesn't.

It is a good habit to make at least some constraints around the token payload structure and the TokenPayload object may be of help here.
By default, the TokenPayload just contains default JWT claims and a custom claim `typ` (type of token).

```python
@dataclass
class TokenPayload:
    iss: str  # Issuer
    sub: str  # Subject
    exp: int  # Expiration Time
    nbf: int  # Not Before
    iat: int  # Issued At
    jti: str  # JWT ID
    typ: str  # Type of token (custom)
```

#### The audience claim

Note that we skipped the `aud` (Audience) claim, as specified in https://www.rfc-editor.org/rfc/rfc7519#section-4.1.
The reason for this is that when you use the `aud` claim, it implies that the generator knows who (which service) will/should be using the token,
which (in my humble opinion) goes a bit against the stateless nature because upon generating the token, you need to supply the token consumer (audience) already,
so it can be encoded in the token as well. The consumer should always provide its own identity (as audience) when verifying tokens.
The JWT library by design, will confirm the supplied audience value (the consumer's identity) against the provided `aud` claim in the token.

If you want to use the `aud` claim anyway, you need to extend the TokenPayload with a "custom" claim.

#### Additional custom claims

While the TokenPayload object is already quite usefull, it can be extended with more custom claims.
For example, when using role-based permissions, the role(s) can be added to the token as well.

Consider the following TokenPayloadRoles object:

```python
@dataclass
class TokenPayloadRoles(TokenPayload):
    roles: List[str]
```

This new TokenPayloadRoles can be used as follows in both the generating service as the consuming service (the validator):

```python
token_service = DummyJsonTokenService(TokenPayloadRoles)
```

The TokenPayloadRoles object needs to be available in all application's contexts.
This means it needs to be either copied over to all applications or injected via a dependency (shared module).

The generating service now needs to provide `roles` when generating the token:

```python
token_service = DummyJsonTokenService(TokenPayloadRoles)
token = token_service.generate(
    {
        "roles": ["admin", "user"],
    }
)
```

Failing to provide a `roles` claim will result in an `InvalidPayloadException` error.

The consuming service can now verify the token and get a TokenPayloadRoles object.

```python
token_service = DummyJsonTokenService(TokenPayloadRoles)
payload = token_service.verify(token)
```

### Symmetric TokenService

TODO

### Asymmetric TokenService

TODO

### Automatic TokenService

TODO

#### JWK Service

TODO
