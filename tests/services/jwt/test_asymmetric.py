import pytest

from fractal_tokens.exceptions import TokenExpiredException, TokenInvalidException


def test_asymmetric_ok(asymmetric_jwt_token_service):
    token = asymmetric_jwt_token_service.generate({})
    assert asymmetric_jwt_token_service.verify(token)


def test_extended_asymmetric_ok(extended_asymmetric_jwt_token_service):
    token = extended_asymmetric_jwt_token_service.generate({})
    assert extended_asymmetric_jwt_token_service.verify(token)


def test_dummy_get_unverified_claims(extended_asymmetric_jwt_token_service):
    token = extended_asymmetric_jwt_token_service.generate({})
    claims = extended_asymmetric_jwt_token_service.get_unverified_claims(token)
    assert set(claims.keys()) == {"exp", "iat", "iss", "jti", "nbf", "typ"}
    assert claims["typ"] == "access"


def test_asymmetric_expired(asymmetric_jwt_token_service):
    token = asymmetric_jwt_token_service.generate({}, seconds_valid=-1)
    with pytest.raises(TokenExpiredException):
        asymmetric_jwt_token_service.verify(token)


def test_asymmetric_verify_wrong_typ(asymmetric_jwt_token_service):
    token = asymmetric_jwt_token_service.generate({})
    with pytest.raises(TokenInvalidException):
        asymmetric_jwt_token_service.verify(token, typ="refresh")
