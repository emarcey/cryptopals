from secrets import randbelow, token_bytes
from random import choice
from typing import Dict, List, Optional, Tuple

from exercises.const import BLOCK_SIZE, DEFAULT_ENCODING
from exercises.set_1 import encrypt_aes128_ecb, decrypt_aes128_ecb, process_repeating_xor, multiline_base64_to_plaintext
from exercises.utils import str_to_chunks, pkcs7_unpad, pkcs7_unpad_aggressive, pkcs7_pad, gen_aes_key, salt_bytes


### Challenge 10
def encrypt_aes128_cbc(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        xor_chunk = process_repeating_xor(pkcs7_pad(chunk, BLOCK_SIZE), iv)
        encrypted_chunk = encrypt_aes128_ecb(xor_chunk, key)
        results.append(encrypted_chunk)
        iv = encrypted_chunk
    return "".join(results)


def decrypt_aes128_cbc(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        decrypted_chunk = decrypt_aes128_ecb(chunk, key)
        if not decrypted_chunk:
            continue
        xor_chunk = process_repeating_xor(decrypted_chunk, iv)
        results.append(xor_chunk)
        iv = chunk
    return pkcs7_unpad("".join(results))


def decrypt_aes128_cbc_aggressive(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        decrypted_chunk = decrypt_aes128_ecb(chunk, key)
        if not decrypted_chunk:
            continue
        xor_chunk = process_repeating_xor(decrypted_chunk, iv)
        results.append(xor_chunk)
        iv = chunk
    return pkcs7_unpad_aggressive("".join(results))


### Challenge 11
def encrypt_ecb_or_cbc(s: str) -> Tuple[str, str]:
    s_bytes = s.encode(DEFAULT_ENCODING)
    key = gen_aes_key()
    salted_s = salt_bytes(s_bytes).decode(DEFAULT_ENCODING)
    result = ""
    enc_type = ""
    if randbelow(2) == 1:
        return encrypt_aes128_ecb(salted_s, key), "ecb"
        enc_type = "ecb"
    return encrypt_aes128_cbc(salted_s, key, gen_aes_key().decode(DEFAULT_ENCODING)), "cbc"


def detect_ecb_or_cbc(s: str) -> str:
    chunks = str_to_chunks(s, BLOCK_SIZE, -1, True)
    score = len(chunks) - len(set(chunks))
    if score > 0:
        return "ecb"
    return "cbc"


### Challenge 12
class Oracle:
    def __init__(self, pad_str: Optional[str] = None):
        self._key = gen_aes_key(choice([16, 24, 32]))
        self._pad_str = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
        if pad_str:
            self._pad_str = pad_str

    def encrypt(self, s: str) -> str:
        return encrypt_aes128_ecb(s + self._pad_str, self._key)


def find_key_block_size(oracle: Oracle, max_size: int = 100) -> int:
    cur_len = -1
    for i in range(1, max_size + 1):
        s = "A" * i
        enc_s = oracle.encrypt(s)
        len_enc_s = len(enc_s)
        if cur_len == -1 or cur_len == len_enc_s:
            cur_len = len_enc_s
            continue
        return len_enc_s - cur_len
    raise ValueError("Could not find block size")


def _make_short_block(block_size: int) -> str:
    return "A" * (block_size - 1)


def make_block_dict(oracle: Oracle, block_size: int, curr_str: str) -> str:
    len_short_block = (block_size - (1 + len(curr_str))) % block_size
    short_block = "A" * len_short_block
    chunk_len = len(short_block) + len(curr_str) + 1

    base = oracle.encrypt(short_block)[:chunk_len]
    for i in range(256):
        enc = oracle.encrypt(short_block + curr_str + chr(i))
        if base == enc[:chunk_len]:
            return chr(i)
    return ""


def byte_at_a_time_decryption(oracle: Oracle) -> str:
    block_size = find_key_block_size(oracle)
    ecb_or_cbc = detect_ecb_or_cbc(oracle.encrypt("A" * 16 * 10))
    if ecb_or_cbc == "cbc":
        raise ValueError(f"Something bad happened")

    mystery_str_len = len(oracle.encrypt(""))
    result_str = ""
    for i in range(mystery_str_len):
        tmp = make_block_dict(oracle, block_size, result_str)
        result_str += tmp

    return pkcs7_unpad(result_str)


### Challenge 13
def kv_parser(s: str, entry_delim: str = "&", kv_delim: str = "=") -> Dict[str, str]:
    obj = {}
    for entry in s.split(entry_delim):
        if not entry:
            continue
        kv = entry.split(kv_delim)
        if len(kv) != 2:
            continue
        obj[kv[0]] = kv[1]
    return obj


def kv_serializer(obj: Dict[str, str], entry_delim: str = "&", kv_delim: str = "=") -> Dict[str, str]:
    entries = []
    for k, v in obj.items():
        entries.append(k + kv_delim + v)
    return entry_delim.join(entries)


def profile_for(email: str, uid: int) -> str:
    obj = {"email": email.replace("=", "").replace("&", ""), "uid": str(uid), "role": "user"}
    return kv_serializer(obj)


class ProfileOracle:
    def __init__(self):
        self._key = gen_aes_key()

    def encrypt(self, email: str, uid: str = 10) -> str:
        return encrypt_aes128_ecb(profile_for(email, uid), self._key)

    def decrypt(self, s: str) -> Dict[str, str]:
        return kv_parser(decrypt_aes128_ecb(s, self._key))


def ecb_cut_and_paste(email: str, oracle: ProfileOracle) -> str:
    block_size = find_key_block_size(oracle)
    block1 = (block_size - len("email=")) * "A"
    encrypted1 = oracle.encrypt(block1 + pkcs7_pad("admin", block_size), 10)

    block2len = len("email=" + email + "&uid=" + "&role=")
    uid_len = block_size - (block2len % block_size)
    uid = int("1" * uid_len)
    initial_len = block2len + uid_len
    encrypted2 = oracle.encrypt(email, uid)
    return encrypted2[:initial_len] + encrypted1[16:32]


def hack_admin_user(email: str) -> Dict[str, str]:
    o = ProfileOracle()
    cut_and_paste = ecb_cut_and_paste(email, o)
    return o.decrypt(cut_and_paste)


### Challenge 14
class PrefixOracle:
    def __init__(self):
        self._key = gen_aes_key(choice([16, 24, 32]))
        self._prefix_str = token_bytes(randbelow(100) + 1).decode(DEFAULT_ENCODING)
        self._suffix_str = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

    def encrypt(self, s: str) -> str:
        return encrypt_aes128_ecb(self._prefix_str + s + self._suffix_str, self._key)


def _find_repeat_start(chunks: List[str]) -> int:
    for i in range(1, len(chunks) - 1):
        if chunks[i] == chunks[i + 1]:
            return i + 1

    raise ValueError("No repeating chunk found.")


def find_prefix_size(oracle: PrefixOracle, block_size: int) -> int:
    base_encrypt = oracle.encrypt("")
    big_encrypt = oracle.encrypt("A" * (16 * (len(base_encrypt) // block_size)))
    chunks = str_to_chunks(big_encrypt, block_size, -1, True)
    repeat_start_chunk = _find_repeat_start(chunks)
    test_chunk = "".join(chunks[:repeat_start_chunk])
    one_chunk_back = block_size * (repeat_start_chunk - 1)

    for i in range(0, block_size * 2 + 1):
        temp_encrypt = oracle.encrypt("A" * i)
        if temp_encrypt[: repeat_start_chunk * block_size] == test_chunk:
            return block_size - i + one_chunk_back


def make_block_dict_with_prefix(oracle: PrefixOracle, prefix_size: int, block_size: int, curr_str: str) -> str:
    len_short_block = (block_size - (1 + len(curr_str) + prefix_size)) % block_size
    short_block = "A" * len_short_block
    chunk_len = len(short_block) + len(curr_str) + 1 + prefix_size

    base = oracle.encrypt(short_block)[:chunk_len]
    for i in range(256):
        enc = oracle.encrypt(short_block + curr_str + chr(i))
        if base == enc[:chunk_len]:
            return chr(i)
    return ""


def byte_at_a_time_decryption_with_prefix(oracle: PrefixOracle) -> str:
    block_size = find_key_block_size(oracle)
    prefix_size = find_prefix_size(oracle, block_size)

    mystery_str_len = len(oracle.encrypt("")) - prefix_size
    result_str = ""
    for i in range(mystery_str_len):
        tmp = make_block_dict_with_prefix(oracle, prefix_size, block_size, result_str)
        result_str += tmp

    return pkcs7_unpad(result_str)


### Challenge 16
class CBCProfileOracle:
    def __init__(self):
        self._key = gen_aes_key(choice([16, 24, 32]))
        self._prefix_str = "comment1=cooking%20MCs;userdata="
        self._suffix_str = ";comment2=%20like%20a%20pound%20of%20bacon"
        self._iv = gen_aes_key().decode(DEFAULT_ENCODING)

    @staticmethod
    def _clean(s: str) -> str:
        return s.replace("=", '"="').replace(";", '";"')

    def encrypt(self, s: str) -> str:
        return encrypt_aes128_cbc(self._prefix_str + self._clean(s) + self._suffix_str, self._key, self._iv)

    def get_kvs(self, s: str) -> Dict[str, str]:
        decrypted = decrypt_aes128_cbc(s, self._key, self._iv)
        return kv_parser(decrypted, ";", "=")


def cbc_find_prefix_len(oracle: CBCProfileOracle, block_size: int) -> int:
    base_encrypt = oracle.encrypt("")
    big_encrypt = oracle.encrypt("A" * (16 * (len(base_encrypt) // block_size)))

    initial_len = 0
    for i in range(len(base_encrypt)):
        if base_encrypt[i] != big_encrypt[i]:
            initial_len = i
            break
    for i in range(1, block_size + 1):
        encrypt_x = oracle.encrypt("A" * i + "X")
        encrypt_y = oracle.encrypt("A" * i + "Y")
        if encrypt_x[: initial_len + i] == encrypt_y[: initial_len + i]:
            return initial_len + block_size - i


def cbc_cut_and_paste(oracle: CBCProfileOracle) -> str:
    block_size = find_key_block_size(oracle)
    prefix_size = cbc_find_prefix_len(oracle, block_size)

    prefix_pad = block_size - (prefix_size % block_size)
    admin_phrase = "?admin?true"
    admin_pad = block_size - (len(admin_phrase) % block_size)
    encrypted = oracle.encrypt("A" * prefix_pad + "A" * admin_pad + admin_phrase)

    full_prefix_len = prefix_size + prefix_pad
    semicolon_location = full_prefix_len - block_size + admin_pad
    semicolon = ord(encrypted[semicolon_location]) ^ ord("?") ^ ord(";")
    equals_location = full_prefix_len - block_size + admin_pad + 6
    equals = ord(encrypted[equals_location]) ^ ord("?") ^ ord("=")
    return (
        encrypted[:semicolon_location]
        + chr(semicolon)
        + encrypted[semicolon_location + 1 : equals_location]
        + chr(equals)
        + encrypted[equals_location + 1 :]
    )


def hack_admin_cbc(oracle: CBCProfileOracle) -> Dict[str, str]:
    cut_and_paste = cbc_cut_and_paste(oracle)
    return oracle.get_kvs(cut_and_paste)
