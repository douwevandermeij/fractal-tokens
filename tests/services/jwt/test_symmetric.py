def test_symmetric_ok(symmetric_jwt_token_service):
    assert symmetric_jwt_token_service.is_healthy()

    token = symmetric_jwt_token_service.generate({})
    assert symmetric_jwt_token_service.verify(token, typ="access")
