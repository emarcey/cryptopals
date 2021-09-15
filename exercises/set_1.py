from typing import Tuple

### Challenge 1
HEX_CHARS = "0123456789abcdef"
B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def hex_to_base64(hex_str: str) -> str:
    curr = 0
    result = ""

    needs = ""
    for hex_char in hex_str:
        dec = int(hex_char, 16)

        if not needs:
            curr = dec
            needs = "2"
            continue
        if needs == "2":
            result += B64_CHARS[(curr << 2) | (dec >> 2)]
            curr = dec & 0x3
            needs = "4"
            continue
        if needs == "4":
            result += B64_CHARS[(curr << 4) | dec]
            curr = 0
            needs = ""
            continue

    if needs == "2":
        result += B64_CHARS[curr << 2] + "="
    elif needs == "4":
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


def xor_scorer(s: str) -> float:
    score = 0
    prev_char_byte = -1
    for c in s:
        char_byte = ord(c)
        # no one is putting control chars in their message
        if _is_control_char(char_byte):
            score -= 2
        elif char_byte < 31 or char_byte > 127:
            score -= 1
        elif (char_byte >= 65 and char_byte <= 90) or (char_byte >= 97 and char_byte <= 122) or char_byte == 32:
            score += 1

        # punctuation very rarely occurs back to back
        if _is_punctuation_byte(char_byte) and _is_punctuation_byte(prev_char_byte):
            # some cases like "((" are okay but still unusual
            if char_byte != prev_char_byte:
                score -= 5
            else:
                score -= 2

        prev_char_byte = char_byte

    return score


def find_xor_char(s: str) -> Tuple[str, float, str]:
    ascii_bytes = hex_to_text(s).encode("utf-8")
    scores = []
    for i in range(256):
        result_string = xor_char(ascii_bytes, i)
        score = xor_scorer(result_string)
        scores.append((result_string.strip(), score, chr(i)))

    sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)
    return sorted_scores[0]


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


def encrypt_repeating_key_xor(text: str, key: str) -> str:
    i = 0
    key_len = len(key)
    result = ""
    for i in range(len(text)):
        tmp_byte = ord(text[i]) ^ ord(key[i % key_len])
        result += chr(tmp_byte)
    return result


def text_to_hex_repeating_key(text: str, key: str) -> str:
    encrypted_text = encrypt_repeating_key_xor(text, key)
    return text_to_hex(encrypted_text)


### Challenge 6


def _byte_distance(i: int) -> int:
    if i == 0:
        return 0
    return i % 2 + _byte_distance(i >> 1)


def calculate_hamming_distance(s1: str, s2: str):
    result = 0
    for i in range(len(s1)):
        result += _byte_distance(ord(s1[i]) ^ ord(s2[i]))
    return result
