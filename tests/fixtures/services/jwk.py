import pytest


@pytest.fixture
def local_jwk_service(rsa_key_pair):
    kid, private_key, public_key = rsa_key_pair

    from cryptography.hazmat.primitives import serialization as crypto_serialization

    from fractal_tokens.services.jwk import LocalJwkService

    yield LocalJwkService(
        [
            {
                "id": kid,
                "public_key": public_key.public_bytes(
                    crypto_serialization.Encoding.PEM,
                    crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8"),
            }
        ]
    )
