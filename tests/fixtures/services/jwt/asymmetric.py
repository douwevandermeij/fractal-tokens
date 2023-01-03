import uuid

import pytest


@pytest.fixture
def rsa_key_pair():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=512,  # use at least 4096 in production, not 512, but this is quicker in tests!
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption(),
    ).decode("utf-8")

    kid = str(uuid.uuid4())

    return kid, private_key, key.public_key()


@pytest.fixture
def extended_asymmetric_jwt_token_service(rsa_key_pair):
    kid, private_key, public_key = rsa_key_pair

    from fractal_tokens.services.jwt.asymmetric import ExtendedAsymmetricJwtTokenService

    yield ExtendedAsymmetricJwtTokenService(
        issuer="test",
        private_key=private_key,
        public_key=public_key,
        kid=kid,
    )
