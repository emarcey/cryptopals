import pytest
from secrets import choice, randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.set_5 import rsa, encrypt_rsa
from exercises.set_6 import UnpaddedRsaOracle, unpadded_rsa_oracle_attack, RsaSignatureOracle, forge_rsa_signature


@pytest.mark.parametrize("execution_number", range(5))
def test_unpadded_rsa_oracle_attack(execution_number: int) -> None:
    public_key, private_key = rsa(prime_length=512)
    oracle = UnpaddedRsaOracle(private_key)
    message = "Hello there, friendo"
    encrypted = encrypt_rsa(message, public_key)
    decrypted = oracle.decrypt(encrypted)
    with pytest.raises(ValueError):
        decrypted = oracle.decrypt(encrypted)

    found = False
    for i in range(5):
        hacked_result = unpadded_rsa_oracle_attack(oracle, public_key, encrypted)
        if message == hacked_result:
            found = True
            break
    if not found:
        raise ValueError("Could not break")


@pytest.mark.parametrize("execution_number", range(5))
def test_rsa_signature_oracle(execution_number: int) -> None:
    m = "Hi mom"
    key_len = 1024
    public_key1, private_key1 = rsa(prime_length=key_len // 2)
    public_key2, private_key2 = rsa(prime_length=key_len // 2)
    oracle1 = RsaSignatureOracle(key_len, private_key1, public_key2)
    oracle2 = RsaSignatureOracle(key_len, private_key2, public_key1)
    encrypted_signature1 = oracle1.sign(m)
    assert oracle2.validate(encrypted_signature1, m)
    encrypted_signature2 = oracle2.sign(m)
    assert oracle1.validate(encrypted_signature2, m)


@pytest.mark.parametrize("execution_number", range(5))
def test_forge_rsa_signature(execution_number: int) -> None:
    m = "Hi mom"
    key_len = 1024
    public_key1, private_key1 = rsa(prime_length=key_len // 2)
    public_key2, private_key2 = rsa(prime_length=key_len // 2)
    oracle = RsaSignatureOracle(key_len, private_key1, public_key2)
    forged_signature = forge_rsa_signature(m, key_len)
    assert oracle.validate(forged_signature, m)
