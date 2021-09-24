import hashlib
import os
import pytest
from secrets import randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import decode_base64_to_aes128_ecb
from exercises.set_4 import (
    AesCtrOracle,
    crack_aes_ctr_oracle,
    CtrProfileOracle,
    hack_admin_ctr,
    hack_cbc_iv_key_oracle,
    CbcIvKeyProfileOracle,
    sha1_with_mac,
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
