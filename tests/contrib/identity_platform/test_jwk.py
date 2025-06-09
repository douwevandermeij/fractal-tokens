def test_jwk():
    from fractal_tokens.contrib.identity_platform.jwk import (
        GoogleIdentityPlatformJwkService,
    )

    assert len(GoogleIdentityPlatformJwkService().get_jwks()) > 0


def test_token_payload():
    from fractal_tokens.contrib.identity_platform.payload import TokenPayload

    assert TokenPayload(
        iss="",
        aud="",
        sub="",
        exp=0,
        nbf=0,
        iat=0,
        jti="",
        typ="",
    )
