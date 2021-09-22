from typing import List, Tuple
from Crypto.Cipher import AES

from exercises.const import BLOCK_SIZE, DEFAULT_ENCODING
from exercises.utils import pkcs7_pad, pkcs7_unpad, str_to_chunks

### Challenge 1
HEX_CHARS = "0123456789abcdef"
B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def hex_to_base64(hex_str: str) -> str:
    curr = 0
    result = ""

    needs = 0
    for hex_char in hex_str:
        dec = int(hex_char, 16)

        if not needs:
            curr = dec
            needs = 2
            continue
        if needs == 2:
            result += B64_CHARS[(curr << 2) | (dec >> 2)]
            curr = dec & 0x3
            needs = 4
            continue
        if needs == 4:
            result += B64_CHARS[(curr << 4) | dec]
            curr = 0
            needs = 0
            continue

    if needs == 2:
        result += B64_CHARS[curr << 2] + "="
    elif needs == 4:
        result += B64_CHARS[curr << 4] + "=="

    return result


### Challenge 2
def _int_to_hex(i: int) -> str:
    q = i // 16
    r = i % 16
    result = ""
    if q == 0:
        return HEX_CHARS[r]
    return int_to_hex(q) + HEX_CHARS[r]


def int_to_hex(i: int) -> str:
    if i == 0:
        return "0"
    return _int_to_hex(i)


def hex_xor(s1: str, s2: str) -> str:
    s1_int = int(s1, 16)
    s2_int = int(s2, 16)
    return int_to_hex(s1_int ^ s2_int)


### Challenge 3
def hex_to_text(s: str) -> str:
    result = ""
    curr = 0
    for i in range(len(s)):
        val = int(s[i], 16) * (16 ** ((i + 1) % 2))
        curr += val
        if i % 2 == 1:
            result += chr(curr)
            curr = 0
    return result


def xor_char(ascii_bytes: str, xor_byte: int) -> str:
    return "".join([chr(b ^ xor_byte) for b in ascii_bytes])


def _is_punctuation_byte(b: int) -> bool:
    if b >= 33 and b <= 47:
        return True
    if b >= 58 and b <= 64:
        return True
    if b >= 91 and b <= 96:
        return True
    if b >= 123 and b <= 126:
        return True
    return False


def _is_control_char(b: int) -> bool:
    return b <= 31 or b == 127


freq_table = {
    "E": 12.02,
    "T": 9.10,
    "A": 8.12,
    "O": 7.68,
    "I": 7.31,
    "N": 6.95,
    "S": 6.28,
    "R": 6.02,
    "H": 5.92,
    "D": 4.32,
    "L": 3.98,
    "U": 2.88,
    "C": 2.71,
    "M": 2.61,
    "F": 2.30,
    "Y": 2.11,
    "W": 2.09,
    "G": 2.03,
    "P": 1.82,
    "B": 1.49,
    "V": 1.11,
    "K": 0.69,
    "X": -10,
    "Q": -10,
    "J": -10,
    "Z": -10,
}


def _get_frequency(c: str) -> float:
    return freq_table.get(c.upper(), 0) / 2 + 1


def xor_scorer(s: str) -> float:
    score = 0
    prev_char_byte = -1
    num_caps = 0
    for c in s:
        char_byte = ord(c)
        # no one is putting control chars in their message
        if _is_control_char(char_byte):
            score -= 20
        elif _is_punctuation_byte(char_byte):
            score -= 20
        elif char_byte > 127:
            score -= 20
        elif char_byte == 32:
            score += 5
        elif char_byte >= 65 and char_byte <= 90:
            score += _get_frequency(c)
            num_caps += 1
        elif char_byte >= 97 and char_byte <= 122:
            score += _get_frequency(c)
        elif char_byte >= 48 and char_byte <= 57:
            score -= 10

        # # punctuation very rarely occurs back to back
        # if _is_punctuation_byte(char_byte) and _is_punctuation_byte(prev_char_byte):
        #     # some cases like "((" are okay but still unusual
        #     if char_byte != prev_char_byte:
        #         score -= 5
        #     else:
        #         score -= 2

        prev_char_byte = char_byte

    if num_caps == len(s):
        score += 20

    return score


def find_xor_char_from_text(s: str) -> Tuple[str, float, str]:
    ascii_bytes = s.encode("utf-8")
    scores = []
    for i in range(256):
        result_string = xor_char(ascii_bytes, i)
        score = xor_scorer(result_string)
        scores.append((result_string.strip(), score, chr(i)))

    sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)
    return sorted_scores[0]


def find_xor_char(s: str) -> Tuple[str, float, str]:
    return find_xor_char_from_text(hex_to_text(s))


### Challenge 4
def find_record_with_xor_char(file_name: str) -> Tuple[int, str, float, str]:
    scores = []
    i = 0
    for line in open(file_name, "r"):
        if not line.strip():
            continue
        tmp = (str(i),) + find_xor_char(line.strip())
        scores.append(tmp)
        i += 1
    sorted_scores = sorted(scores, key=lambda x: x[2], reverse=True)
    return sorted_scores[0]


### Challenge 5
def text_to_hex(s: str) -> str:
    result = ""
    for c in s:
        result += bytes.hex(c.encode())
    return result


def process_repeating_xor(text: str, key: str) -> str:
    i = 0
    key_len = len(key)
    result = ""
    for i in range(len(text)):
        tmp_byte = ord(text[i]) ^ ord(key[i % key_len])
        result += chr(tmp_byte)
    return result


def text_to_hex_repeating_key(text: str, key: str) -> str:
    encrypted_text = process_repeating_xor(text, key)
    return text_to_hex(encrypted_text)


### Challenge 6
def base64_to_plaintext(b64_str: str) -> str:
    curr = 0
    result = ""

    needs = 0
    stripped_b64_str = b64_str.strip("=")

    for b64_char in stripped_b64_str:
        dec = B64_CHARS.index(b64_char)
        if not needs:
            curr = dec
            needs = 2
            continue
        if needs == 2:
            result += chr((curr << 2) | (dec >> 4))
            curr = dec & 15
            needs = 4
            continue
        if needs == 4:
            result += chr((curr << 4) | (dec >> 2))
            curr = dec & 0x3
            needs = 6
            continue
        if needs == 6:
            result += chr((curr << 6) | dec)
            curr = 0
            needs = 0
            continue
    return result


def multiline_base64_to_plaintext(b64_s: str) -> str:
    return "".join([base64_to_plaintext(y) for y in b64_s.split("\n")])


def _bit_distance(i: int) -> int:
    if i == 0:
        return 0
    return i % 2 + _bit_distance(i >> 1)


def calculate_bit_hamming_distance(s1: str, s2: str) -> float:
    result = 0
    for i in range(len(s1)):
        result += _bit_distance(ord(s1[i]) ^ ord(s2[i]))
    return result


def find_key_len_candidates(
    s: str, min_key_len: int = 2, max_key_len: int = 40, num_chunks: int = 6
) -> List[Tuple[int, float]]:
    scores = []
    for i in range(min_key_len, min(max_key_len, len(s) // 4) + 1):
        tmp_distances = []
        chunks = str_to_chunks(s, i, num_chunks, False)
        chunk_ct = len(chunks)
        for j in range(chunk_ct):
            for k in range(j + 1, chunk_ct):
                tmp_distances.append(calculate_bit_hamming_distance(chunks[j], chunks[k]))

        scores.append((i, (sum(tmp_distances) / len(tmp_distances)) / i))
    sorted_scores = sorted(scores, key=lambda x: x[1])
    return sorted_scores[:5]


def transpose_chunks(chunks: List[str]) -> List[str]:
    if not chunks:
        return []
    key_size = len(chunks[0])
    transposed_chunks = ["" for i in range(key_size)]
    for chunk in chunks:
        for i in range(min(key_size, len(chunk))):
            transposed_chunks[i] += chunk[i]

    return transposed_chunks


def find_repeating_xor_key(s: str) -> str:
    key_len_candidates = find_key_len_candidates(s)
    all_scores = []
    for key_len_candidate in key_len_candidates:
        key_len_scores = []
        key_len = key_len_candidate[0]
        s_chunks = str_to_chunks(s, key_len, -1, True)
        s_transposed = transpose_chunks(s_chunks)
        all_scores.append([find_xor_char_from_text(transposed_chunk) for transposed_chunk in s_transposed])

    avg_scores = []
    for scores in all_scores:
        key = ""
        sum_scores = 0
        len_scores = 0
        for score in scores:
            key += score[2]
            sum_scores += score[1]
            len_scores += 1

        avg_scores.append((key, sum_scores / len_scores))

    return sorted(avg_scores, key=lambda x: x[1], reverse=True)


def decrypt_repeating_xor(s: str) -> Tuple[str, str]:
    key_candidates = find_repeating_xor_key(s)
    if not key_candidates:
        raise ValueError("No keys :(")

    key = key_candidates[0][0]
    return process_repeating_xor(s, key), key


def decrypt_hex_repeating_xor(hex_s: str) -> Tuple[str, str]:
    return decrypt_repeating_xor(hex_to_text(hex_s))


def decrypt_b64_repeating_xor(b64_s: str) -> Tuple[str, str]:
    return decrypt_repeating_xor(multiline_base64_to_plaintext(b64_s))


### Challenge 7
def decrypt_aes128_ecb(s: str, key: str) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(s.encode(DEFAULT_ENCODING)).decode(DEFAULT_ENCODING))


def encrypt_aes128_ecb(s: str, key: str) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    len_s = len(s)
    if len(s) % BLOCK_SIZE != 0:
        s = pkcs7_pad(s, len(s) + (BLOCK_SIZE - (len(s) % BLOCK_SIZE)))
    return cipher.encrypt(s.encode(DEFAULT_ENCODING)).decode(DEFAULT_ENCODING)


def decode_base64_to_aes128_ecb(b64_s: str, key: str) -> str:
    decoded = multiline_base64_to_plaintext(b64_s)
    return decrypt_aes128_ecb(decoded, key)


### Challenge 8
def text_to_hex(s: str) -> str:
    result = ""
    for c in s:
        ord_c = ord(c)
        result += HEX_CHARS[ord_c >> 4]
        result += HEX_CHARS[ord_c & 15]  # 15 = 0b00001111

    return result


def find_ecb_encoded_hex_text(lines: List[str]) -> Tuple[int, str]:
    results = tuple()
    i = 0
    max_score = -1
    for line in lines:
        # double block size bc it's hex
        chunks = str_to_chunks(line.strip(), BLOCK_SIZE * 2, -1, True)
        score = len(chunks) - len(set(chunks))
        if score > max_score:
            results = (i, line)
            max_score = score
        i += 1
    return results
