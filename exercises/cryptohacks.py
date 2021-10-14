from asn1crypto.x509 import Certificate
import base64
from binascii import unhexlify
import codecs
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib
import json
import os
from PIL import Image, ImageChops
import telnetlib
from typing import Any, Dict, List, Tuple

from exercises.const import DEFAULT_ENCODING
from exercises.set_5 import mod_exp, extended_gcd
from exercises.utils import str_to_chunks


s_box = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)

inv_s_box = (
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
)


def legendre_symbol(a: int, p: int) -> int:
    return mod_exp(a, (p - 1) // 2, p)


def gcd(a: int, b: int) -> Tuple[int, int, int]:
    r1 = a
    r2 = b

    while r2 != 0:
        q = r1 // r2
        r3 = r1
        r1 = r2
        r2 = r3 - q * r2

    return r1


def tonelli_shanks(n: int, p: int):
    q = p - 1
    s = 0
    while q % 2 == 0:
        q = q // 2
        s += 1

    if s == 1:
        return pow(n, (p + 1) // 4, p)

    for z in range(2, p):
        if legendre_symbol(z, p) == p - 1:
            break

    m = s
    c = mod_exp(z, q, p)
    t = mod_exp(n, q, p)
    r = mod_exp(n, ((q + 1) // 2), p)

    while (t - 1) % p != 0:
        if t == 0:
            return 0
        if t == 1:
            return r
        for i in range(1, m):
            t2 = (t * t) % p
            for i in range(1, m):
                if (t2 - 1) % p == 0:
                    break
                t2 = (t2 * t2) % p

        b = mod_exp(int(c), 2 ** (m - i - 1), p)
        m = i
        c = (b ** 2) % p
        t = (t * (b ** 2)) % p
        r = (r * b) % p

    return r


def chinese_remainder(vals: List[Tuple[int, int]]):
    product_n = 1
    for val in vals:
        product_n *= val[1]

    result = 0
    for val in vals:
        tmp_n = val[1]
        tmp_N = product_n // tmp_n
        ex = extended_gcd(tmp_n, tmp_N)
        result += val[0] * tmp_N * ex[2]

    return result


def adriens_signs(nums: List[int], a: int, p: int):
    bin_result = ""
    for num in nums:
        if legendre_symbol(num, p) in [1, 0, -1]:
            bin_result += "1"
        else:
            bin_result += "0"

    chunks = str_to_chunks(bin_result, 8)
    return "".join([chr(int(c, 2)) for c in chunks])


def readline(tn):
    return tn.read_until(b"\n")


def json_recv(tn):
    line = readline(tn)
    return json.loads(line.decode())


def json_send(tn, hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)


def network_attacks(request: Dict[str, Any], host: str = "socket.cryptohack.org", port: int = 11112) -> Dict[str, Any]:
    tn = telnetlib.Telnet(host, port)

    json_send(tn, request)

    response = json_recv(tn)
    return response


def network_attacks_decode(host: str = "socket.cryptohack.org", port: int = 11112) -> Dict[str, Any]:
    tn = telnetlib.Telnet(host, port)

    for i in range(100):
        received = json_recv(tn)
        encoding = received["type"]
        msg = received["encoded"]
        if encoding == "base64":
            decoded = base64.b64decode(msg).decode()
        elif encoding == "hex":
            decoded = unhexlify(msg).decode()
        elif encoding == "rot13":
            decoded = codecs.decode(msg, "rot_13")
        elif encoding == "bigint":
            decoded = long_to_bytes(int(msg, 16)).decode()
        elif encoding == "utf-8":
            decoded = "".join([chr(b) for b in msg])
        json_send(tn, {"decoded": decoded})

    received = json_recv(tn)
    return received


def xor_file(filename1: str, filename2: str) -> None:
    # https://crypto.stackexchange.com/a/88493
    im1 = Image.open(f"{os.getcwd()}/data/{filename1}")
    im2 = Image.open(f"{os.getcwd()}/data/{filename2}")
    key_image = ImageChops.add(ImageChops.subtract(im1, im2), ImageChops.subtract(im2, im1))
    key_image.show()


def privacy_enhanced_mail(filename: str) -> RSA.RsaKey:
    raw_key = ""
    with open(f"{os.getcwd()}/data/{filename}", "r") as f:
        raw_key = f.read()

    key = RSA.importKey(raw_key)
    return key


def get_der_cert_public_key(filename: str) -> Dict[str, Any]:
    raw_key = b""
    with open(f"{os.getcwd()}/data/{filename}", "rb") as f:
        raw_key = f.read()

        cert = Certificate.load(raw_key)
    return cert.public_key.native["public_key"]


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [[ord(j) if type(j) != int else j for j in list(text[i : i + 4])] for i in range(0, len(text), 4)]


def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    result = ""
    for row in matrix:
        for column in row:
            result += chr(column)
    return result


def add_round_key(s, k):
    results = []
    for i in range(len(s)):
        row_result = []
        s_row = s[i]
        k_row = k[i]
        for j in range(len(s_row)):
            row_result.append(s_row[j] ^ k_row[j])

        results.append(row_result)
    return results


def sub_bytes(s, sbox):
    results = []
    for row in s:
        row_result = []
        for column in row:
            row_result.append(sbox[column])
        results.append(row_result)
    return results


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
    s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
    s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]


# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


def expand_key(master_key, num_rounds):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00,
        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x40,
        0x80,
        0x1B,
        0x36,
        0x6C,
        0xD8,
        0xAB,
        0x4D,
        0x9A,
        0x2F,
        0x5E,
        0xBC,
        0x63,
        0xC6,
        0x97,
        0x35,
        0x6A,
        0xD4,
        0xB3,
        0x7D,
        0xFA,
        0xEF,
        0xC5,
        0x91,
        0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    i = 1
    while len(key_columns) < (num_rounds + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i ^ j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4 * i : 4 * (i + 1)] for i in range(len(key_columns) // 4)]


def aes_decrypt(key, ciphertext, sub_box, num_rounds):
    round_keys = expand_key(
        key, num_rounds
    )  # Remember to start from the last round key and work backwards through them when decrypting

    # Convert ciphertext to state matrix
    state = bytes2matrix(ciphertext)

    # Initial add round key step
    state = add_round_key(state, round_keys[-1])

    for i in range(num_rounds - 1, 0, -1):
        print(i)
        inv_shift_rows(state)
        state = sub_bytes(state, sub_box)
        state = add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Run final round (skips the InvMixColumns step)
    inv_shift_rows(state)
    state = sub_bytes(state, sub_box)
    state = add_round_key(state, round_keys[0])

    # Convert state matrix to plaintext
    plaintext = matrix2bytes(state)
    return plaintext


def aes_password_brute_force(ciphertext: str) -> Tuple[bytes, bytes]:
    with open("/usr/share/dict/words") as f:
        words = [w.strip() for w in f.readlines()]
    ciphertext_bytes = bytes.fromhex(ciphertext)
    for keyword in words:
        key = hashlib.md5(keyword.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext_bytes)
        if decrypted.decode(DEFAULT_ENCODING).startswith("crypto"):
            return decrypted, key

    raise ValueError("No key found")
