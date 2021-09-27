from secrets import choice, randbelow
import struct
from typing import Dict, List, Optional, Tuple

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import hex_to_int, hex_to_text, int_to_hex, process_repeating_xor
from exercises.set_2 import encrypt_aes128_cbc, decrypt_aes128_cbc, kv_parser, find_key_block_size, cbc_find_prefix_len
from exercises.set_3 import ctr_stream
from exercises.utils import gen_aes_key, str_to_chunks


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


### Challenge 28
def _sha1_preprocess(m: bytes, l: Optional[int] = None) -> bytes:
    original_bit_message_length = l
    if not original_bit_message_length:
        original_bit_message_length = len(m) * 8

    m += b"\x80"
    new_bit_message_length = len(m) * 8
    while new_bit_message_length % 512 != 448:
        m += b"\x00"
        new_bit_message_length += 8

    m += struct.pack(">Q", original_bit_message_length)
    return m


def _left_rotate(v: int, count: int) -> int:
    return ((v << count) & 0xFFFFFFFF) | (v >> (32 - count))


def sha1(
    s: str,
    h0: int = 0x67452301,
    h1: int = 0xEFCDAB89,
    h2: int = 0x98BADCFE,
    h3: int = 0x10325476,
    h4: int = 0xC3D2E1F0,
    l: Optional[int] = None,
) -> str:

    message = s.encode(DEFAULT_ENCODING)
    preprocessed_message = _sha1_preprocess(message, l)
    # process chunks of 512 bits

    for chunk in str_to_chunks(preprocessed_message, 512 // 8):

        words = [struct.unpack(">I", w)[0] for w in str_to_chunks(chunk, 32 // 8)] + [0] * 64

        for i in range(16, 80):
            words[i] = _left_rotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1)

        # initialize chunk hash values
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for i in range(80):
            f = 0
            k = 0
            if i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = _left_rotate(a, 5) + f + e + k + words[i] & 0xFFFFFFFF
            e = d
            d = c
            c = _left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    hh = (h0 << 128) ^ (h1 << 96) ^ (h2 << 64) ^ (h3 << 32) ^ h4
    return int_to_hex(hh).zfill(40)


def sha1_with_mac(s: str, mac: str) -> str:
    return sha1(mac + s)


### Challenge 29
class Sha1Oracle:
    def __init__(self) -> None:
        with open("/usr/share/dict/words") as dictionary:
            self._mac = choice(dictionary.readlines()).strip()

    def sha1(self, s: str) -> str:
        return sha1_with_mac(s, self._mac)

    def validate(self, message: str, hashed_message: str) -> bool:
        return self.sha1(message) == hashed_message


def _forge_initial_variables_sha1(hashed_message: str) -> Tuple[int, int, int, int, int]:
    hashed_int = hex_to_int(hashed_message)
    a = hashed_int >> 128
    b = (hashed_int >> 96) & 0xFFFFFFFF
    c = (hashed_int >> 64) & 0xFFFFFFFF
    d = (hashed_int >> 32) & 0xFFFFFFFF
    e = hashed_int & 0xFFFFFFFF
    return (a, b, c, d, e)


def length_extension_attack_mac_sha1(
    oracle: Sha1Oracle, message: str, hashed_message: str, new_message: str, max_key_len: int = 100
) -> Tuple[str, str]:
    message_bytes = message.encode(DEFAULT_ENCODING)
    a, b, c, d, e = _forge_initial_variables_sha1(hashed_message)
    new_message_bytes = new_message.encode(DEFAULT_ENCODING)

    for key_len in range(100):
        fake_message = (_sha1_preprocess(b"A" * key_len + message_bytes)[key_len:] + new_message_bytes).decode(
            DEFAULT_ENCODING
        )
        fake_hash = sha1(new_message, a, b, c, d, e, (key_len + len(fake_message)) * 8)
        if oracle.validate(fake_message, fake_hash):
            return fake_message, fake_hash

    raise ValueError("No match found")


### Challenge 30
# Pseudocode from: https://datatracker.ietf.org/doc/html/rfc1320
def _md4_preprocess(m: bytes, l: Optional[int] = None) -> bytes:
    original_bit_message_length = l
    if not original_bit_message_length:
        original_bit_message_length = len(m) * 8

    m += b"\x80"
    new_bit_message_length = len(m) * 8
    while new_bit_message_length % 512 != 448:
        m += b"\x00"
        new_bit_message_length += 8

    m += struct.pack("<Q", original_bit_message_length)
    return m


def _md4_f(x: int, y: int, z: int) -> int:
    # In each bit position F acts as a conditional: if X then Y else Z
    return (x & y) | ((~x) & z)


def _md4_g(x: int, y: int, z: int) -> int:
    # In each bit position G acts as a majority function: if at least two of X, Y, Z are on,
    # then G has a "1" bit in that bit position, else G has a "0" bit.
    return (x & y) | (x & z) | (y & z)


def _md4_h(x: int, y: int, z: int) -> int:
    # The function H is the bit-wise XOR or "parity" function
    return x ^ y ^ z


def _md4_round_1(word_a: int, word_b: int, word_c: int, word_d: int, words: List[int]) -> Tuple[int, int, int, int]:
    for i in range(16):
        if i % 4 == 0:
            word_a = _left_rotate((word_a + _md4_f(word_b, word_c, word_d) + words[i]) & 0xFFFFFFFF, 3)
        elif i % 4 == 1:
            word_d = _left_rotate((word_d + _md4_f(word_a, word_b, word_c) + words[i]) & 0xFFFFFFFF, 7)
        elif i % 4 == 2:
            word_c = _left_rotate((word_c + _md4_f(word_d, word_a, word_b) + words[i]) & 0xFFFFFFFF, 11)
        else:
            word_b = _left_rotate((word_b + _md4_f(word_c, word_d, word_a) + words[i]) & 0xFFFFFFFF, 19)
    return (word_a, word_b, word_c, word_d)


def _md4_round_2(word_a: int, word_b: int, word_c: int, word_d: int, words: List[int]) -> Tuple[int, int, int, int]:
    tmp_int = 0x5A827999
    for idx in range(16):
        i = ((idx % 4) * 4) + (idx // 4)
        if i < 4:
            word_a = _left_rotate((word_a + _md4_g(word_b, word_c, word_d) + words[i] + tmp_int) & 0xFFFFFFFF, 3)
        elif i < 8:
            word_d = _left_rotate((word_d + _md4_g(word_a, word_b, word_c) + words[i] + tmp_int) & 0xFFFFFFFF, 5)
        elif i < 12:
            word_c = _left_rotate((word_c + _md4_g(word_d, word_a, word_b) + words[i] + tmp_int) & 0xFFFFFFFF, 9)
        else:
            word_b = _left_rotate((word_b + _md4_g(word_c, word_d, word_a) + words[i] + tmp_int) & 0xFFFFFFFF, 13)
    return (word_a, word_b, word_c, word_d)


def _md4_round_3(word_a: int, word_b: int, word_c: int, word_d: int, words: List[int]) -> Tuple[int, int, int, int]:
    tmp_int = 0x6ED9EBA1
    for i in [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]:
        if i < 4:
            word_a = _left_rotate((word_a + _md4_h(word_b, word_c, word_d) + words[i] + tmp_int) & 0xFFFFFFFF, 3)
        elif i < 8:
            word_c = _left_rotate((word_c + _md4_h(word_d, word_a, word_b) + words[i] + tmp_int) & 0xFFFFFFFF, 11)
        elif i < 12:
            word_d = _left_rotate((word_d + _md4_h(word_a, word_b, word_c) + words[i] + tmp_int) & 0xFFFFFFFF, 9)
        else:
            word_b = _left_rotate((word_b + _md4_h(word_c, word_d, word_a) + words[i] + tmp_int) & 0xFFFFFFFF, 15)
    return (word_a, word_b, word_c, word_d)


def md4(
    s: str,
    word_a: str = 0x67452301,
    word_b: str = 0xEFCDAB89,
    word_c: str = 0x98BADCFE,
    word_d: str = 0x10325476,
    l: Optional[int] = None,
) -> str:
    message = s.encode(DEFAULT_ENCODING)
    preprocessed_message = _md4_preprocess(message, l)

    for chunk in str_to_chunks(preprocessed_message, 512 // 8):
        words = [struct.unpack("<I", w)[0] for w in str_to_chunks(chunk, 32 // 8)]

        word_aa = word_a
        word_bb = word_b
        word_cc = word_c
        word_dd = word_d

        word_a, word_b, word_c, word_d = _md4_round_1(word_a, word_b, word_c, word_d, words)
        word_a, word_b, word_c, word_d = _md4_round_2(word_a, word_b, word_c, word_d, words)
        word_a, word_b, word_c, word_d = _md4_round_3(word_a, word_b, word_c, word_d, words)

        word_a = (word_a + word_aa) & 0xFFFFFFFF
        word_b = (word_b + word_bb) & 0xFFFFFFFF
        word_c = (word_c + word_cc) & 0xFFFFFFFF
        word_d = (word_d + word_dd) & 0xFFFFFFFF

    return struct.pack("<4I", word_a, word_b, word_c, word_d).hex()


def md4_with_mac(s: str, mac: str) -> str:
    return md4(mac + s)


class Md4Oracle:
    def __init__(self) -> None:
        with open("/usr/share/dict/words") as dictionary:
            self._mac = choice(dictionary.readlines()).strip()

    def md4(self, s: str) -> str:
        return md4_with_mac(s, self._mac)

    def validate(self, message: str, hashed_message: str) -> bool:
        return self.md4(message) == hashed_message


def _forge_initial_variables_md4(hashed_message: str) -> Tuple[int, int, int, int, int]:
    return struct.unpack("<4I", hex_to_text(hashed_message).encode(DEFAULT_ENCODING))


def length_extension_attack_mac_md4(
    oracle: Md4Oracle, message: str, hashed_message: str, new_message: str, max_key_len: int = 100
) -> Tuple[str, str]:
    message_bytes = message.encode(DEFAULT_ENCODING)
    a, b, c, d = _forge_initial_variables_md4(hashed_message)
    new_message_bytes = new_message.encode(DEFAULT_ENCODING)

    for key_len in range(100):
        fake_message = (_md4_preprocess(b"A" * key_len + message_bytes)[key_len:] + new_message_bytes).decode(
            DEFAULT_ENCODING
        )
        fake_hash = md4(new_message, a, b, c, d, (key_len + len(fake_message)) * 8)
        if oracle.validate(fake_message, fake_hash):
            return fake_message, fake_hash

    raise ValueError("No match found")
