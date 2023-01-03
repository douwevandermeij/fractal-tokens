import pytest


@pytest.fixture
def automatic_jwt_token_service(secret_key, local_jwk_service):
    from fractal_tokens.services.jwt.automatic import AutomaticJwtTokenService

    yield AutomaticJwtTokenService(
        issuer="test",
        secret=secret_key,
        jwk_service=local_jwk_service,
    )
