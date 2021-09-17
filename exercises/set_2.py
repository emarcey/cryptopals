from secrets import randbelow
from typing import Tuple

from exercises.const import BLOCK_SIZE, DEFAULT_ENCODING
from exercises.set_1 import encrypt_aes128_ecb, decrypt_aes128_ecb, process_repeating_xor
from exercises.utils import str_to_chunks, pkcs7_unpad, pkcs7_pad, gen_aes_key, salt_bytes


### Challenge 9
def encrypt_aes_128_cbc(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        print(pkcs7_pad(chunk, BLOCK_SIZE))
        xor_chunk = process_repeating_xor(pkcs7_pad(chunk, BLOCK_SIZE), iv)
        encrypted_chunk = encrypt_aes128_ecb(xor_chunk, key)
        results.append(encrypted_chunk)
        iv = encrypted_chunk
    return "".join(results)


def decrypt_aes_128_cbc(s: str, key: str, iv: str) -> str:
    results = []
    for chunk in str_to_chunks(s, BLOCK_SIZE, -1, True):
        decrypted_chunk = decrypt_aes128_ecb(chunk, key)
        if not decrypted_chunk:
            continue
        xor_chunk = process_repeating_xor(decrypted_chunk, iv)
        results.append(xor_chunk)
        iv = chunk
    return pkcs7_unpad("".join(results))


### Challenge 10
def encrypt_ecb_or_cbc(s: str) -> Tuple[str, str]:
    s_bytes = s.encode(DEFAULT_ENCODING)
    key = gen_aes_key()
    salted_s = salt_bytes(s_bytes).decode(DEFAULT_ENCODING)
    result = ""
    enc_type = ""
    if randbelow(2) == 1:
        result = encrypt_aes128_ecb(salted_s, key)
        enc_type = "ecb"
    else:
        result = encrypt_aes_128_cbc(salted_s, key, gen_aes_key().decode(DEFAULT_ENCODING))
        enc_type = "cbc"
    return result, enc_type


def detect_ecb_or_cbc(s: str) -> str:
    chunks = str_to_chunks(s.strip(), BLOCK_SIZE * 2, -1, True)
    score = len(chunks) - len(set(chunks))
    if score > 0:
        return "ecb"
    return "cbc"
