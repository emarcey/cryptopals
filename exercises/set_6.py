import hashlib
import re
import time
from secrets import randbelow

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
