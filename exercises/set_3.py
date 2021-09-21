from random import choice
from typing import Tuple

from exercises.const import BLOCK_SIZE, DEFAULT_ENCODING
from exercises.set_1 import process_repeating_xor, decrypt_aes128_ecb, encrypt_aes128_ecb
from exercises.utils import (
    str_to_chunks,
    pkcs7_unpad,
    pkcs7_pad,
    gen_aes_key,
    salt_bytes,
    is_pkcs7_padded,
)
from exercises.set_2 import decrypt_aes128_cbc, encrypt_aes128_cbc


def decrypt_aes128_cbc_no_pad(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        decrypted_chunk = decrypt_aes128_ecb(chunk, key)
        if not decrypted_chunk:
            continue
        xor_chunk = process_repeating_xor(decrypted_chunk, iv)
        results.append(xor_chunk)
        iv = chunk
    return "".join(results)


def encrypt_aes128_cbc_no_pad(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        xor_chunk = process_repeating_xor(chunk, iv)
        encrypted_chunk = encrypt_aes128_ecb(xor_chunk, key)
        results.append(encrypted_chunk)
        iv = encrypted_chunk
    return "".join(results)


### Challenge 17
class CBCPaddingOracle:
    def __init__(self):
        self.string_opts = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ]
        self._key = gen_aes_key(choice([16, 24, 32]))
        self._iv = gen_aes_key().decode(DEFAULT_ENCODING)

    @staticmethod
    def _clean(s: str) -> str:
        return s.replace("=", '"="').replace(";", '";"')

    def encrypt(self) -> Tuple[str, str]:
        chosen_string = pkcs7_pad(choice(self.string_opts), 16)
        iv = gen_aes_key().decode(DEFAULT_ENCODING)
        return encrypt_aes128_cbc(chosen_string, self._key, iv), iv

    def decrypt(self, s: str, iv: str) -> str:
        return decrypt_aes128_cbc_no_pad(s, self._key, iv)

    def decrypt_check_valid_padding(self, s: str, iv: str) -> bool:
        decrypted = self.decrypt(s, iv)
        return is_pkcs7_padded(decrypted)


def _make_iv(iv: str, block_size: int, pad_len: int, possible_byte: int, curr_str: str) -> str:
    idx = block_size - pad_len
    force_char = ord(iv[idx]) ^ possible_byte ^ pad_len
    forced_iv = iv[:idx] + (chr(force_char))
    for i in range(len(curr_str)):
        forced_iv += chr(ord(iv[idx + i + 1]) ^ ord(curr_str[i]) ^ pad_len)
    return forced_iv


def attack_block(block: str, iv: str, oracle: CBCPaddingOracle) -> str:
    block_size = len(block)
    curr_str = ""
    for pad_len in range(1, BLOCK_SIZE + 1):
        tmp_possible_bytes = []
        for possible_byte in range(256):
            forced_iv = _make_iv(iv, block_size, pad_len, possible_byte, curr_str)
            if oracle.decrypt_check_valid_padding(block, forced_iv):
                tmp_possible_bytes.append(possible_byte)
        if len(tmp_possible_bytes) > 1:
            for tmp_possible_byte in tmp_possible_bytes:
                for possible_byte2 in range(256):
                    forced_iv = _make_iv(iv, block_size, pad_len + 1, possible_byte2, chr(tmp_possible_byte) + curr_str)
                    if oracle.decrypt_check_valid_padding(block, forced_iv):
                        tmp_possible_bytes = [tmp_possible_byte]
                        break

        curr_str = chr(tmp_possible_bytes[0]) + curr_str
    return curr_str


def attack_padding_oracle(ciphertext: str, iv: str, oracle: CBCPaddingOracle) -> str:
    all_blocks = [iv] + str_to_chunks(ciphertext, 16, -1, True)

    curr_str = ""
    for i in range(1, len(all_blocks)):
        curr_str += attack_block(all_blocks[i], all_blocks[i - 1], oracle)
    return pkcs7_unpad(curr_str)
