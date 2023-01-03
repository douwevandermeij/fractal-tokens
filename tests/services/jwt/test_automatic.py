def test_symmetric_automatic(symmetric_jwt_token_service, automatic_jwt_token_service):
    assert symmetric_jwt_token_service.is_healthy()
    assert automatic_jwt_token_service.is_healthy()

    token = symmetric_jwt_token_service.generate({})
    assert automatic_jwt_token_service.verify(token, typ="access")


def test_extended_asymmetric_automatic(
    extended_asymmetric_jwt_token_service, automatic_jwt_token_service
):
    assert extended_asymmetric_jwt_token_service.is_healthy()
    assert automatic_jwt_token_service.is_healthy()

    token = extended_asymmetric_jwt_token_service.generate({})
    assert automatic_jwt_token_service.verify(token, typ="access")
