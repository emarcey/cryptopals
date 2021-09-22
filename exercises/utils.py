import time
import secrets
from typing import List


def str_to_chunks(s: str, chunk_size: int, max_chunks: int, allow_partials: bool) -> List[str]:
    chunks = []
    num_chunks = 0
    for i in range(0, len(s), chunk_size):
        if max_chunks != -1 and num_chunks >= max_chunks:
            break

        chunk = s[i : i + chunk_size]
        if not allow_partials and len(chunk) < chunk_size:
            break
        chunks.append(chunk)
        num_chunks += 1
    return chunks


# Challenge 9
def pkcs7_pad(s: str, block_size: int) -> str:
    len_s = len(s)
    if len_s > 0 and len_s % block_size == 0:
        return s
    num_pads = block_size - (len_s % block_size)
    return (s.encode() + (bytes([num_pads]) * num_pads)).decode()


def pkcs7_unpad(s: str) -> str:
    if len(s) == 0:
        return s
    byte_s = s.encode()
    pad_range = byte_s[-byte_s[-1] :]
    if len(set(pad_range)) != 1:
        return s
    return (byte_s[: -byte_s[-1]]).decode()


def is_pkcs7_padded(s: str) -> bool:
    if len(s) == 0:
        return s
    byte_s = s.encode()
    pad_range = byte_s[-byte_s[-1] :]
    return all(pad_range[b] == len(pad_range) for b in range(0, len(pad_range)))


def gen_aes_key(key_len: int = 16) -> bytes:
    return secrets.token_bytes(key_len)


def _make_salt(min_len: int = 5, max_len: int = 10) -> bytes:
    salt_len = secrets.randbelow(max_len - min_len + 1) + min_len
    return secrets.token_bytes(salt_len)


def salt_bytes(b: bytes) -> bytes:
    return _make_salt() + b + _make_salt()


def rand_sleep(min_val: int, max_val: int) -> None:
    t = secrets.randbelow(max_val - min_val) + min_val
    time.sleep(t)
