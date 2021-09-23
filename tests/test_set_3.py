import time
import os
import pytest
from secrets import randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.utils import pkcs7_unpad, gen_aes_key, rand_sleep
from exercises.set_1 import base64_to_plaintext
from exercises.set_3 import (
    attack_padding_oracle,
    CbcPaddingOracle,
    ctr_stream,
    decrypt_ctr_texts,
    decrypt_ctr_texts_trunc,
    crack_rng,
    MersenneRng,
    clone_rng,
    crack_rng_16_bit_encrypt,
    crack_password_token,
)


@pytest.mark.parametrize("execution_number", range(10))
def test_attack_padding_oracle(execution_number: int) -> None:
    oracle = CbcPaddingOracle()
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


# both of these methods are imperfect, due to variances in str length,
# so the results will be iffy for longer texts
@pytest.mark.parametrize("filename", [("set3_challenge19.txt"), ("set3_challenge20.txt")])
def test_decrypt_ctr_texts(filename: str) -> None:
    with open(f"{os.getcwd()}/data/{filename}", "r") as f:
        texts = [x.strip() for x in f]
        decoded_texts = [base64_to_plaintext(x) for x in texts]
        print(decrypt_ctr_texts(decoded_texts))


@pytest.mark.parametrize("filename", [("set3_challenge19.txt"), ("set3_challenge20.txt")])
def test_decrypt_ctr_texts_trunc(filename: str) -> None:
    with open(f"{os.getcwd()}/data/{filename}", "r") as f:
        texts = [x.strip() for x in f]
        decoded_texts = [base64_to_plaintext(x) for x in texts]
        min_len = min(map(len, decoded_texts))
        truncated_texts = [x[:min_len] for x in decoded_texts]
        assert decrypt_ctr_texts_trunc(decoded_texts)[0][0] == truncated_texts


@pytest.mark.parametrize("execution_number", range(5))
def test_mersenne_rng(execution_number: int) -> None:
    a = MersenneRng(seed=0)
    b = MersenneRng(seed=0)
    c = MersenneRng(seed=1)
    val_a = a.get()
    val_b = b.get()
    val_c = c.get()

    assert val_a == val_b
    assert val_a != val_c


@pytest.mark.parametrize("execution_number", range(5))
def test_crack_rng(execution_number: int) -> None:
    min_sleep = 1
    max_sleep = 10
    rng = MersenneRng(seed=int(time.time()))
    rand_sleep(min_sleep, max_sleep)
    assert crack_rng(rng.get(), min_sleep, max_sleep) == rng._seed


@pytest.mark.parametrize("execution_number", range(10))
def test_clone_rng(execution_number: int) -> None:
    seed = int(time.time() * 1000)
    initial_rng = MersenneRng(seed)
    cloned_rng = clone_rng(initial_rng)
    assert cloned_rng.mt == initial_rng.mt
    for i in range(624):
        assert initial_rng.get() == cloned_rng.get()
    time.sleep(1)


@pytest.mark.parametrize("execution_number", range(10))
def test_rng_encrypt(execution_number: int) -> None:
    seed = randbelow(2 ** 16)
    rng1 = MersenneRng(seed)
    random_text = token_bytes(randbelow(256) + 64).decode(DEFAULT_ENCODING)
    rng2 = MersenneRng(seed)
    assert rng2.encrypt(rng1.encrypt(random_text)) == random_text


@pytest.mark.parametrize("execution_number", range(10))
def test_rng_encrypt_with_prefix(execution_number: int) -> None:
    seed = randbelow(2 ** 16)
    rng1 = MersenneRng(seed)
    random_text = token_bytes(randbelow(256) + 64).decode(DEFAULT_ENCODING)
    rng2 = MersenneRng(seed)
    assert rng2.encrypt(rng1.encrypt_with_prefix(random_text)).endswith(random_text)


def test_crack_rng_16_bit_encrypt() -> None:
    seed = randbelow(2 ** 16)
    rng1 = MersenneRng(seed)
    random_text = token_bytes(randbelow(256) + 64).decode(DEFAULT_ENCODING)
    encrypted_text = rng1.encrypt_with_prefix(random_text)
    assert crack_rng_16_bit_encrypt(random_text, encrypted_text) == seed


@pytest.mark.parametrize("execution_number", range(5))
def test_crack_password_token(execution_number: int) -> None:
    min_sleep = 1
    max_sleep = 10
    rng = MersenneRng(seed=int(time.time()))
    rand_sleep(min_sleep, max_sleep)
    password_token = rng.get_password_token(randbelow(64) + 16)
    assert crack_password_token(password_token) == rng._seed
