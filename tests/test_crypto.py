import RNS as ret

from akita_ddns.crypto import identity_from_public_key, verify_signature_with_public_key


def test_identity_from_public_key_reconstructs_identity():
    identity = ret.Identity()
    reconstructed = identity_from_public_key(identity.get_public_key())

    assert reconstructed is not None
    assert reconstructed.hash == identity.hash


def test_verify_signature_with_public_key_accepts_valid_signature():
    identity = ret.Identity()
    message = b"akita"
    signature = identity.sign(message)

    assert verify_signature_with_public_key(message, signature, identity.get_public_key())