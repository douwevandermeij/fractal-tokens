def test_extended_asymmetric_ok(extended_asymmetric_jwt_token_service):
    assert extended_asymmetric_jwt_token_service.is_healthy()

    token = extended_asymmetric_jwt_token_service.generate({})
    assert extended_asymmetric_jwt_token_service.verify(token, typ="access")
