import pytest

from exercises.utils import pkcs7_unpad
from exercises.set_3 import CBCPaddingOracle, attack_padding_oracle


@pytest.mark.parametrize("execution_number", range(10))
def test_attack_padding_oracle(execution_number: int) -> None:
    oracle = CBCPaddingOracle()
    ciphertext, initial_iv = oracle.encrypt()
    assert pkcs7_unpad(oracle.decrypt(ciphertext, initial_iv)) == attack_padding_oracle(ciphertext, initial_iv, oracle)
