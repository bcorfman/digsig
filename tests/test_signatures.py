from dslib.signatures import generate_keys, sign, verify


def test_signing_process():
    private_key, public_key = generate_keys()
    message = b'This is a secret message'
    digsig = sign(message, private_key)
    assert verify(message, digsig, public_key) is True
