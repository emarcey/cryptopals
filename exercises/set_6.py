import hashlib
import time
from secrets import randbelow

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import hex_to_text, int_to_hex, text_to_hex, hex_to_int
from exercises.set_5 import decrypt_rsa, encrypt_rsa, invmod, mod_exp, rsa, RsaKey


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
