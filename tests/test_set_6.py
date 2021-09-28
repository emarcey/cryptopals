import pytest
from secrets import choice, randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.set_5 import rsa, encrypt_rsa
from exercises.set_6 import UnpaddedRsaOracle, unpadded_rsa_oracle_attack


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
