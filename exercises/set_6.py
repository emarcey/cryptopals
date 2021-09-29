import hashlib
import re
import time
from secrets import randbelow
from typing import Tuple

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import hex_to_text, int_to_hex, text_to_hex, hex_to_int
from exercises.set_4 import sha1
from exercises.set_5 import decrypt_rsa, encrypt_rsa, invmod, mod_exp, rsa, RsaKey, find_n_root

### Challenge 41
class UnpaddedRsaOracle:
    def __init__(self, private_key: RsaKey) -> None:
        self.private_key = private_key
        self._cache = {}

    def decrypt(self, c: int) -> str:
        if c in self._cache:
            raise ValueError(f"Message, {c}, already seen at timestamp, {self._cache[c]}")

        decrypted = decrypt_rsa(c, self.private_key)

        self._cache[c] = time.time()
        return decrypted


def unpadded_rsa_oracle_attack(oracle: UnpaddedRsaOracle, public_key: RsaKey, c: int):
    n = public_key.n
    e = public_key.v
    s = randbelow(n - 3) + 2
    c_prime = (mod_exp(s, e, n) * c) % n
    p_prime = oracle.decrypt(c_prime)
    p_prime_int = hex_to_int(text_to_hex(p_prime))
    p = (p_prime_int * invmod(s, n)) % n
    return hex_to_text(int_to_hex(p))


PKCS_SHA1 = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

RSA_SIGNATURE_REGEX = re.compile("\x00\x01\xff+\x00(.{15})(.{20})", re.DOTALL)

### Challenge 42
class RsaSignatureOracle:
    def __init__(self, key_len: int, private_key: RsaKey, sender_public_key: RsaKey):
        self.key_len = key_len
        self.private_key = private_key
        self.sender_public_key = sender_public_key

    def sign(self, m: str) -> str:
        m_hash = PKCS_SHA1 + hex_to_text(sha1(m))
        padding = "\xff" * (self.key_len // 8 - len(m_hash) - 3)

        signature = "\x00\x01" + padding + "\x00" + m_hash
        return decrypt_rsa(hex_to_int(text_to_hex(signature)), self.private_key)

    def validate(self, encrypted_signature: str, m: str) -> bool:
        new_signature = hex_to_text(int_to_hex(encrypt_rsa(encrypted_signature, self.sender_public_key)).zfill(254))
        if len(new_signature) == 127:
            new_signature = "\x00" + new_signature

        matches = RSA_SIGNATURE_REGEX.match(new_signature)
        if not matches:
            return False

        pkcs_id = matches.group(1)
        if pkcs_id != PKCS_SHA1:
            return False
        hashed = matches.group(2)
        return hashed == hex_to_text(sha1(m))


def forge_rsa_signature(message: str, key_len: int) -> str:
    m_hash = PKCS_SHA1 + hex_to_text(sha1(message))
    forged_signature = "\x00\x01\xff\x00"
    forged_signature += m_hash
    garbage = "\x00" * (key_len // 8 - len(forged_signature))
    full_forged_signature = forged_signature + garbage
    forged_int = hex_to_int(text_to_hex(full_forged_signature))
    forged_n_root = find_n_root(forged_int, 3)

    hex_val = int_to_hex(forged_n_root)
    if len(hex_val) % 2 == 1:
        hex_val = "0" + hex_val

    return hex_to_text(hex_val)


### Challenge 43
DEFAULT_P = 0x800000000000000089E1855218A0E7DAC38136FFAFA72EDA7859F2171E25E65EAC698C1702578B07DC2A1076DA241C76C62D374D8389EA5AEFFD3226A0530CC565F3BF6B50929139EBEAC04F48C3C84AFB796D61E5A4F9A8FDA812AB59494232C7D2B4DEB50AA18EE9E132BFA85AC4374D7F9091ABC3D015EFC871A584471BB1
DEFAULT_Q = 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
DEFAULT_G = 0x5958C9D3898B224B12672C0B98E06C60DF923CB8BC999D119458FEF538B8FA4046C8DB53039DB620C094C9FA077EF389B5322A559946A71903F990F1F7E0E025E2D7F7CF494AFF1A0470F5B64C36B625A097F1651FE775323556FE00B3608C887892878480E99041BE601A62166CA6894BDD41A7054EC89F756BA9FC95302291


def dsa(p: int = DEFAULT_P, q: int = DEFAULT_Q, g: int = DEFAULT_G) -> Tuple[int, int]:
    x = randbelow(q - 1) + 1
    y = mod_exp(g, x, p)
    return x, y


class DsaSignature:
    def __init__(self, r: int, s: int) -> None:
        self.r = r
        self.s = s


class DsaSignatureOracle:
    def __init__(
        self,
        private_key: int,
        sender_public_key: int,
        p: int = DEFAULT_P,
        q: int = DEFAULT_Q,
        g: int = DEFAULT_G,
    ):
        self.private_key = private_key
        self.sender_public_key = sender_public_key
        self._p = p
        self._q = q
        self._g = g

    def sign(self, m: str) -> DsaSignature:
        r = 0
        s = 0
        while r == 0 or s == 0:
            k = randbelow(self._q - 1) + 1
            self._k = k
            r = mod_exp(self._g, k, self._p) % self._q
            s = (invmod(k, self._q) * (hex_to_int(sha1(m)) + self.private_key * r)) % self._q

        return DsaSignature(r, s)

    def validate(self, signature: DsaSignature, m: str) -> bool:
        r = signature.r
        s = signature.s
        if r <= 0 or r > self._q:
            return False
        if s <= 0 or s > self._q:
            return False

        w = invmod(s, self._q)
        u1 = (hex_to_int(sha1(m)) * w) % self._q
        u2 = (r * w) % self._q

        v = ((mod_exp(self._g, u1, self._p) * mod_exp(self.sender_public_key, u2, self._p)) % self._p) % self._q
        return r == v


def recover_dsa_private_key(signature: DsaSignature, m: str, k: int, q: int = DEFAULT_Q) -> int:
    return (invmod(signature.r, q) * ((signature.s * k) - hex_to_int(sha1(m)))) % q


def brute_force_recover_dsa_private_key(
    public_key: int,
    signature: DsaSignature,
    m: str,
    min_key_val: int = 0,
    max_key_val: int = 2 ** 16,
    p: int = DEFAULT_P,
    q: int = DEFAULT_Q,
    g: int = DEFAULT_G,
) -> str:
    for k in range(min_key_val, max_key_val):
        private_key = recover_dsa_private_key(signature, m, k, q)
        if mod_exp(g, private_key, p) == public_key:
            return private_key

    raise ValueError("Unable to find private key")