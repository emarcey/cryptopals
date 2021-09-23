from itertools import product
from random import choice
from struct import pack
import time
from typing import Any, List, Tuple
from secrets import randbelow, token_bytes

from exercises.const import BLOCK_SIZE, DEFAULT_ENCODING, TRIGRAMS
from exercises.set_1 import (
    decrypt_aes128_ecb,
    encrypt_aes128_ecb,
    find_xor_char_from_text,
    process_repeating_xor,
    transpose_chunks,
    xor_char,
    xor_scorer,
)
from exercises.set_2 import decrypt_aes128_cbc, encrypt_aes128_cbc
from exercises.utils import gen_aes_key, is_pkcs7_padded, pkcs7_pad, pkcs7_unpad, str_to_chunks, rand_sleep


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
class CbcPaddingOracle:
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


def attack_block(block: str, iv: str, oracle: CbcPaddingOracle) -> str:
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


def attack_padding_oracle(ciphertext: str, iv: str, oracle: CbcPaddingOracle) -> str:
    all_blocks = [iv] + str_to_chunks(ciphertext, 16, -1, True)

    curr_str = ""
    for i in range(1, len(all_blocks)):
        curr_str += attack_block(all_blocks[i], all_blocks[i - 1], oracle)
    return pkcs7_unpad(curr_str)


### Challenge 18
def ctr_stream(s: str, key: str, nonce: int, block_size: int = 16) -> str:
    counter = 0
    curr_str = ""

    curr_enc = encrypt_aes128_ecb(pack("<QQ", nonce, counter // block_size).decode(DEFAULT_ENCODING), key)
    for c in s:
        curr_str += chr(ord(curr_enc[counter % block_size]) ^ ord(c))
        counter += 1
        if counter % 16 == 0:
            curr_enc = encrypt_aes128_ecb(pack("<QQ", nonce, counter // block_size).decode(DEFAULT_ENCODING), key)

    return curr_str


def _find_idx_candidates(idx_text: List[str], num_candidates: int = 3) -> Tuple[int, str, float, str]:
    candidates = []
    for i in range(256):
        tmp = "".join([chr(ord(x[0]) ^ i) if x else "" for x in idx_text])
        score = xor_scorer(tmp)
        candidates.append((i, chr(i), score, tmp))

    return sorted(candidates, key=lambda x: x[2], reverse=True)[:num_candidates]


def get_block_candidates(encrypted_texts: List[str], num_candidates: int = 5) -> List[Tuple[int, str, float, str]]:
    block_candidates = []
    for i in range(max(map(len, encrypted_texts))):
        tmp_idx_text = [x[i] if i < len(x) else "" for x in encrypted_texts]
        tmp_num_candidates = num_candidates
        if len(set(tmp_idx_text)) > 5:
            tmp_num_candidates = 1
        block_candidates.append(_find_idx_candidates(tmp_idx_text, tmp_num_candidates))

    return block_candidates


def get_trigram_frequency(s: str) -> int:
    score = 0
    upper_s = s.upper()
    for i in range(len(s) - 2):
        if upper_s[i : i + 3] in TRIGRAMS:
            score += 1
    return score * 10


def decrypt_ctr_texts(encrypted_texts: List[str]) -> List[str]:
    # imperfect
    all_block_candidates = get_block_candidates(encrypted_texts, 1)

    results = []
    for block_candidates in product(*all_block_candidates):
        keystream = "".join([x[1] for x in block_candidates])
        decrypt_results = [process_repeating_xor(encrypted_text, keystream) for encrypted_text in encrypted_texts]
        scores = [get_trigram_frequency(x) + xor_scorer(x) for x in decrypt_results]
        results.append((decrypt_results, sum(scores) / len(scores), keystream))
    return sorted(results, key=lambda x: x[1], reverse=True)[:5]


### Challenge 20
# The same as 19, but with a trunc function that doesn't do everything
def decrypt_ctr_texts_trunc(encrypted_texts: List[str]) -> List[str]:
    min_len = min(map(len, encrypted_texts))
    truncated_texts = [x[:min_len] for x in encrypted_texts]
    return decrypt_ctr_texts(truncated_texts)


### Challenge 21

MERSENNE_W = 32
MERSENNE_N = 624
MERSENNE_M = 397
MERSENNE_R = 31
MERSENNE_A = 0x9908B0DF
MERSENNE_U = 11
MERSENNE_D = 0xFFFFFFFF
MERSENNE_S = 7
MERSENNE_B = 0x9D2C5680
MERSENNE_T = 15
MERSENNE_C = 0xEFC60000
MERSENNE_L = 18
MERSENNE_F = 1812433253

MERSENNE_LOWEST_W_BITS = 0xFFFFFFFF


class MersenneRng:
    def __init__(self, seed: int):
        self.mt = [0 for i in range(MERSENNE_N)]
        self.index = MERSENNE_N + 1
        self.lower_mask = (1 << MERSENNE_R) - 1
        self.upper_mask = (~self.lower_mask) & MERSENNE_LOWEST_W_BITS
        self._seed = seed
        self._lowest_bits_mask = (1 << MERSENNE_W) - 1
        self.seed(seed)

    def seed(self, seed: int) -> None:
        self.index = MERSENNE_N
        self.mt[0] = seed
        for i in range(1, MERSENNE_N):
            tmp = (MERSENNE_F * self.mt[i - 1]) ^ (self.mt[i - 1] >> (MERSENNE_W - 2)) + i
            self.mt[i] = tmp & self._lowest_bits_mask

    def twist(self) -> None:
        for i in range(MERSENNE_N):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % MERSENNE_N] & self.lower_mask)
            x_a = x >> 1
            if x % 2 != 0:
                x_a = x_a ^ MERSENNE_A
            self.mt[i] = self.mt[(i + MERSENNE_M) % MERSENNE_N] ^ x_a
        self.index = 0

    @staticmethod
    def temper_y(y: int) -> int:
        y ^= (y >> MERSENNE_U) & MERSENNE_D
        y ^= (y << MERSENNE_S) & MERSENNE_B
        y ^= (y << MERSENNE_T) & MERSENNE_C
        y ^= y >> MERSENNE_L
        return y

    def get(self) -> None:
        if self.index > MERSENNE_N:
            raise ValueError("Generator was never seeded")
        if self.index == MERSENNE_N:
            self.twist()

        y = self.temper_y(self.mt[self.index])

        self.index += 1
        return y & self._lowest_bits_mask

    def get_8bit(self) -> None:
        return (self.get() >> 8) & 0xFF

    def encrypt(self, s: str) -> str:
        curr_str = ""
        for c in s:
            curr_str += chr(ord(c) ^ self.get_8bit())

        return curr_str

    def encrypt_with_prefix(self, s: str, min_prefix_len: int = 16, max_prefix_len: int = 64) -> str:
        prefix = token_bytes(randbelow(max_prefix_len - min_prefix_len) + min_prefix_len).decode(DEFAULT_ENCODING)
        print()
        return self.encrypt(prefix + s)

    def get_password_token(self, token_len: int = 32) -> str:
        curr_str = ""
        for i in range(token_len):
            curr_str += chr(self.get_8bit())

        return curr_str


### Challenge 22
def crack_rng(initial_val: int, min_sleep: int = 40, max_sleep: int = 1000) -> int:
    curr_time = int(time.time())
    for i in range(min_sleep, max_sleep):
        new_seed = curr_time - i
        new_rng = MersenneRng(new_seed)
        if new_rng.get() == initial_val:
            return new_seed

    raise ValueError(f"Could not find seed.")


### Challenge 23
def untemper(y: int) -> int:
    y ^= y >> MERSENNE_L
    y = ((y << MERSENNE_T) & MERSENNE_C) ^ y
    s_mask = (1 << MERSENNE_S) - 1
    y ^= (y << MERSENNE_S) & MERSENNE_B & (s_mask << MERSENNE_S)
    y ^= (y << MERSENNE_S) & MERSENNE_B & (s_mask << (MERSENNE_S * 2))
    y ^= (y << MERSENNE_S) & MERSENNE_B & (s_mask << (MERSENNE_S * 3))
    y ^= (y << MERSENNE_S) & MERSENNE_B & (s_mask << (MERSENNE_S * 4))
    u_mask = (1 << MERSENNE_U) - 1
    y ^= (y >> MERSENNE_U) & MERSENNE_D & (u_mask << (MERSENNE_U * 2))
    y ^= (y >> MERSENNE_U) & MERSENNE_D & (u_mask << (MERSENNE_U))
    y ^= (y >> MERSENNE_U) & u_mask
    return y


def clone_rng(rng: MersenneRng) -> MersenneRng:
    vals = []
    for i in range(MERSENNE_N):
        val = rng.get()
        vals.append((val, untemper(val)))

    new_rng = MersenneRng(1)
    new_rng.mt = [val[1] for val in vals]
    return new_rng


### Challenge 24
def crack_rng_16_bit_encrypt(initial_text: str, encrypted_text: str) -> int:
    len_initial_text = len(initial_text)
    len_encrypted_text = len(encrypted_text)
    test_text = "A" * (len_encrypted_text - len_initial_text) + initial_text
    for i in range(65536):
        test_rng = MersenneRng(i)
        test_encrypted_text = test_rng.encrypt(test_text)
        if encrypted_text[-len_initial_text:] == test_encrypted_text[-len_initial_text:]:
            return i
    raise ValueError("No 16 bit key worked :(")


def generate_random_password_token(curr_time: int, token_len: int = 32) -> str:
    rng = MersenneRng(curr_time)
    return rng.encrypt_with_prefix("", token_len, token_len)


def crack_password_token(password_token: str, time_range: int = 2048) -> int:
    curr_time = int(time.time())
    token_len = len(password_token)
    for i in range(0, time_range):
        new_seed = curr_time - i
        new_rng = MersenneRng(new_seed)

        if new_rng.get_password_token(token_len) == password_token:
            return new_seed

    raise ValueError(f"Could not find seed.")
