import pytest


def test_symmetric_automatic(symmetric_jwt_token_service, automatic_jwt_token_service):
    token = symmetric_jwt_token_service.generate({})
    assert automatic_jwt_token_service.verify(token)


def test_extended_asymmetric_automatic(
    extended_asymmetric_jwt_token_service, automatic_jwt_token_service
):
    token = extended_asymmetric_jwt_token_service.generate({})
    assert automatic_jwt_token_service.verify(token)


def test_automatic_get_unverified_claims(automatic_jwt_token_service):
    token = automatic_jwt_token_service.generate({})
    claims = automatic_jwt_token_service.get_unverified_claims(token)
    assert set(claims.keys()) == {"exp", "iat", "iss", "jti", "nbf", "typ"}
    assert claims["typ"] == "access"


def test_automatic_error(automatic_jwt_token_service):
    from fractal_tokens.exceptions import TokenInvalidException

    with pytest.raises(TokenInvalidException):
        automatic_jwt_token_service.verify("token")


def test_automatic_no_public_key_error(
    extended_asymmetric_jwt_token_service,
    automatic_jwt_token_service,
    empty_local_jwk_service,
):
    automatic_jwt_token_service.jwk_service = empty_local_jwk_service
    from fractal_tokens.exceptions import NotAllowedException

    token = extended_asymmetric_jwt_token_service.generate({})
    with pytest.raises(NotAllowedException):
        automatic_jwt_token_service.verify(token)
