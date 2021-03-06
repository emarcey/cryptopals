import hashlib
import hmac
import os
import pytest
from secrets import randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import decode_base64_to_aes128_ecb
from exercises.set_4 import (
    AesCtrOracle,
    CbcIvKeyProfileOracle,
    crack_aes_ctr_oracle,
    CtrProfileOracle,
    hack_admin_ctr,
    hack_cbc_iv_key_oracle,
    hmac_sha1,
    HmacSha1Oracle,
    length_extension_attack_mac_md4,
    length_extension_attack_mac_sha1,
    md4,
    Md4Oracle,
    sha1_with_mac,
    Sha1Oracle,
    hmac_sha1_timing_hack,
)


@pytest.mark.parametrize("given_text,given_offset,given_newtext,expected", [("abcdefghijkl", 4, "111", "abcd111hijkl")])
def test_aes_ctr_oracle_edit(given_text: str, given_offset: int, given_newtext: str, expected: str) -> None:
    oracle = AesCtrOracle()
    ciphertext = oracle.ctr_process(given_text)
    edited_ciphertext = oracle.edit(ciphertext, given_offset, given_newtext)
    assert expected == oracle.ctr_process(edited_ciphertext)


def test_crack_aes_ctr_oracle() -> None:
    with open(f"{os.getcwd()}/data/set4_challenge25.txt", "r") as f:
        texts = decode_base64_to_aes128_ecb(f.read(), "YELLOW SUBMARINE")
        oracle = AesCtrOracle()
        ciphertext = oracle.ctr_process(texts)
        assert crack_aes_ctr_oracle(oracle, ciphertext) == texts


@pytest.mark.parametrize("execution_number", range(10))
def test_hack_admin_ctr(execution_number: int) -> None:
    o = CtrProfileOracle()
    tmp = o.encrypt(";admin;")
    assert "admin" not in o.get_kvs(tmp)
    result = hack_admin_ctr(o)
    assert result["admin"] == "true"


@pytest.mark.parametrize("execution_number", range(10))
def test_hack_cbc_iv_key_oracle(execution_number: int) -> None:
    o = CbcIvKeyProfileOracle()
    assert hack_cbc_iv_key_oracle(o) == o._key.decode(DEFAULT_ENCODING)


@pytest.mark.parametrize("execution_number", range(10))
def test_hack_cbc_iv_key_oracle(execution_number: int) -> None:
    s = token_bytes(randbelow(256) + 32)
    mac = token_bytes(randbelow(256) + 32)
    assert sha1_with_mac(s.decode(DEFAULT_ENCODING), mac.decode(DEFAULT_ENCODING)) == hashlib.sha1(mac + s).hexdigest()


@pytest.mark.parametrize("execution_number", range(10))
def test_length_extension_attack_mac_sha1(execution_number: int) -> None:
    oracle = Sha1Oracle()
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_message = ";admin=true"
    hashed_message = oracle.sha1(message)
    fake_message, fake_hash = length_extension_attack_mac_sha1(oracle, message, hashed_message, new_message)
    assert fake_message.endswith(new_message)


@pytest.mark.parametrize(
    "given, expected",
    [
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
        ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
        ("message digest", "d9130a8164549fe818874806e1c7014b"),
        ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ],
)
def test_md4(given: str, expected: str) -> None:
    assert md4(given) == expected


@pytest.mark.parametrize("execution_number", range(10))
def test_length_extension_attack_mac_md4(execution_number: int) -> None:
    oracle = Md4Oracle()
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    new_message = ";admin=true"
    hashed_message = oracle.md4(message)
    fake_message, fake_hash = length_extension_attack_mac_md4(oracle, message, hashed_message, new_message)
    assert fake_message.endswith(new_message)


@pytest.mark.parametrize("execution_number", range(10))
def test_hmac_sha1(execution_number: int) -> None:
    key = token_bytes(randbelow(256) + 8)
    message = token_bytes(randbelow(256) + 32)
    print(key)
    print(message)
    assert (
        hmac_sha1(key.decode(DEFAULT_ENCODING), message.decode(DEFAULT_ENCODING))
        == hmac.new(key, message, hashlib.sha1).hexdigest()
    )


@pytest.mark.parametrize("execution_number", range(10))
def test_hmac_sha1_oracle_true(execution_number: int) -> None:
    oracle = HmacSha1Oracle()
    message = token_bytes(randbelow(256) + 32).decode(DEFAULT_ENCODING)

    message_hash = oracle.hash(message)
    assert oracle.validate(message, message_hash)


@pytest.mark.parametrize("execution_number", range(10))
def test_hmac_sha1_oracle_false(execution_number: int) -> None:
    oracle = HmacSha1Oracle()
    message1 = token_bytes(randbelow(256) + 32).decode(DEFAULT_ENCODING)
    message_hash1 = oracle.hash(message1)
    message2 = token_bytes(randbelow(256) + 32).decode(DEFAULT_ENCODING)
    message_hash2 = oracle.hash(message2)
    assert not oracle.validate(message1, message_hash2)


@pytest.mark.parametrize("sleep_time, num_rounds", [(0.005, 3), (0.0005, 10)])
def test_hmac_sha1_timing_hack(sleep_time: float, num_rounds: int) -> None:
    oracle = HmacSha1Oracle(sleep_time)
    raw_message = token_bytes(randbelow(256) + 32).decode(DEFAULT_ENCODING)
    hashed_message = oracle.hash(raw_message)
    max_len = 10
    assert hmac_sha1_timing_hack(oracle, raw_message, num_rounds, max_len) == hashed_message[:max_len]
