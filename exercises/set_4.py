from secrets import randbelow
from typing import Dict

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import process_repeating_xor
from exercises.set_2 import encrypt_aes128_cbc, decrypt_aes128_cbc, kv_parser, find_key_block_size, cbc_find_prefix_len
from exercises.set_3 import ctr_stream
from exercises.utils import gen_aes_key


### Challenge 25
class AesCtrOracle:
    def __init__(self) -> None:
        self._key = gen_aes_key()
        self._nonce = randbelow(2 ** 8)

    def ctr_process(self, s: str) -> None:
        return ctr_stream(s, self._key, self._nonce)

    def edit(self, ciphertext: str, offset: int, newtext: str) -> str:
        decrypted = self.ctr_process(ciphertext)
        return self.ctr_process(decrypted[:offset] + newtext + decrypted[offset + len(newtext) :])


def crack_aes_ctr_oracle(oracle: AesCtrOracle, ciphertext: str) -> str:
    return oracle.edit(ciphertext, 0, ciphertext)


### Challenge 26
class CtrProfileOracle:
    def __init__(self):
        self._key = gen_aes_key()
        self._nonce = randbelow(2 ** 8)
        self._prefix_str = "comment1=cooking%20MCs;userdata="
        self._suffix_str = ";comment2=%20like%20a%20pound%20of%20bacon"
        self._iv = gen_aes_key().decode(DEFAULT_ENCODING)

    @staticmethod
    def _clean(s: str) -> str:
        return s.replace("=", '"="').replace(";", '";"')

    def encrypt(self, s: str) -> None:
        return ctr_stream(self._prefix_str + self._clean(s) + self._suffix_str, self._key, self._nonce)

    def ctr_process(self, s: str) -> None:
        return ctr_stream(s, self._key, self._nonce)

    def edit(self, ciphertext: str, offset: int, newtext: str) -> str:
        decrypted = self.ctr_process(ciphertext)
        return self.ctr_process(decrypted[:offset] + self._clean(newtext) + decrypted[offset + len(newtext) :])

    def get_kvs(self, s: str) -> Dict[str, str]:
        decrypted = self.ctr_process(s)
        return kv_parser(decrypted, ";", "=")


def get_prefix_len(oracle: CtrProfileOracle) -> int:
    enc_a = oracle.encrypt("A")
    enc_b = oracle.encrypt("B")
    for i in range(len(enc_a)):
        if enc_a[i] != enc_b[i]:
            return i
    raise ValueError("Unable to find prefix len")


def hack_admin_ctr(oracle: CtrProfileOracle) -> Dict[str, str]:
    prefix_len = get_prefix_len(oracle)
    admin_phrase = "A?admin?true"
    ciphertext = oracle.encrypt(admin_phrase)
    semicolon_idx = prefix_len + 1
    semicolon = chr(ord(ciphertext[semicolon_idx]) ^ ord("?") ^ ord(";"))
    equals_idx = semicolon_idx + 6
    equals = chr(ord(ciphertext[equals_idx]) ^ ord("?") ^ ord("="))
    hacked_str = (
        ciphertext[:semicolon_idx]
        + semicolon
        + ciphertext[semicolon_idx + 1 : equals_idx]
        + equals
        + ciphertext[equals_idx + 1 :]
    )
    result = oracle.get_kvs(hacked_str)
    return result


### Challenge 27
class CbcIvKeyProfileOracle:
    def __init__(self):
        self._key = gen_aes_key()
        self._iv = self._key.decode(DEFAULT_ENCODING)
        self._prefix_str = "comment1=cooking%20MCs;userdata="
        self._suffix_str = ";comment2=%20like%20a%20pound%20of%20bacon"

    @staticmethod
    def _is_ascii_compliant(s: str) -> bool:
        return all(ord(c) < 128 for c in s)

    @staticmethod
    def _clean(s: str) -> str:
        return s.replace("=", '"="').replace(";", '";"')

    def encrypt(self, s: str) -> str:
        return encrypt_aes128_cbc(self._prefix_str + self._clean(s) + self._suffix_str, self._key, self._iv)

    def decrypt(self, s: str) -> str:
        decrypted = decrypt_aes128_cbc(s, self._key, self._iv)
        if not self._is_ascii_compliant(decrypted):
            raise ValueError(f"Text is not ASCII-compliant: {decrypted}")
        return decrypted


def hack_cbc_iv_key_oracle(oracle: CbcIvKeyProfileOracle) -> str:
    dummy_text = "A" * 16 + "B" * 16 + "C" * 16
    encrypted_text = oracle.encrypt(dummy_text)

    block_size = find_key_block_size(oracle)
    prefix_size = cbc_find_prefix_len(oracle, block_size)

    block_1 = encrypted_text[prefix_size : prefix_size + block_size]
    new_text = block_1 + "\x00" * 16 + block_1

    error_text = ""
    try:
        oracle.decrypt(new_text)
    except ValueError as e:
        error_text = str(e).replace("Text is not ASCII-compliant: ", "")

    if not error_text:
        raise ValueError("Oracle did not raise ASCII compliance error")

    return process_repeating_xor(error_text[:block_size], error_text[-block_size:])
