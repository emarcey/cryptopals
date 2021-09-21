import pytest
from secrets import randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.utils import pkcs7_unpad, gen_aes_key
from exercises.set_1 import base64_to_plaintext
from exercises.set_3 import CBCPaddingOracle, attack_padding_oracle, ctr_stream


@pytest.mark.parametrize("execution_number", range(10))
def test_attack_padding_oracle(execution_number: int) -> None:
    oracle = CBCPaddingOracle()
    ciphertext, initial_iv = oracle.encrypt()
    assert pkcs7_unpad(oracle.decrypt(ciphertext, initial_iv)) == attack_padding_oracle(ciphertext, initial_iv, oracle)


def test_ctr_stream() -> None:
    assert (
        ctr_stream(
            base64_to_plaintext("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="),
            "YELLOW SUBMARINE",
            0,
        )
        == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    )


@pytest.mark.parametrize("execution_number", range(100))
def test_ctr_stream_random(execution_number: int) -> None:
    key = gen_aes_key()
    nonce = randbelow(1000) + 1
    text = token_bytes(randbelow(100) + 25).decode(DEFAULT_ENCODING)
    assert ctr_stream(ctr_stream(text, key, nonce), key, nonce) == text
