from secrets import randbelow
from typing import Tuple

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import hex_to_text
from exercises.set_2 import decrypt_aes128_cbc, encrypt_aes128_cbc
from exercises.set_4 import sha1
from exercises.utils import gen_aes_key, pkcs7_unpad

# Challenge 33
# https://rosettacode.org/wiki/Modular_exponentiation#Python
# https://en.wikipedia.org/wiki/Modular_exponentiation
def _mod_exp(b: int, e: int, m: int) -> int:
    x = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            x = (x * b) % m
        e = e >> 1
        b = (b * b) % m
    return x


def diffie_helman(p: int = 37, g: int = 5) -> Tuple[str, str, str]:
    a = randbelow(p)
    public_A = _mod_exp(g, a, p)
    b = randbelow(p)
    public_B = _mod_exp(g, b, p)
    private_key = _mod_exp(public_B, a, p)
    private_key2 = _mod_exp(public_A, b, p)
    if private_key != private_key2:
        raise ValueError("Something went wrong")

    return public_A, public_B, private_key


## Challenge 34
class DiffieHelmanBot:
    def __init__(self, p: int = 37, g: int = 5) -> None:
        self._p = p
        self._g = g
        self._a = randbelow(p)
        self._private_key = None
        self._private_key_hash = None

    def get_public_key(self) -> int:
        return _mod_exp(self._g, self._a, self._p)

    def get_private_key(self, public_key: int) -> str:
        if not self._private_key:
            self._private_key = _mod_exp(public_key, self._a, self._p)
            self._private_key_hash = hex_to_text(sha1(str(self._private_key)))[:16]
        return self._private_key

    def encrypt_message(self, message: str) -> str:
        iv = gen_aes_key().decode(DEFAULT_ENCODING)
        return encrypt_aes128_cbc(message, self._private_key_hash.encode(DEFAULT_ENCODING), iv) + iv


def _diffie_helman_decrypt(bot: DiffieHelmanBot, encrypted_message: str, message: str) -> Tuple[str, str]:
    for i in range(2):
        hacked_key = hex_to_text(sha1(str(i)))[:16].encode(DEFAULT_ENCODING)
        iv = encrypted_message[-16:]
        hacked_message = decrypt_aes128_cbc(encrypted_message[:-16], hacked_key, iv, should_unpad=False)
        if hacked_message.startswith(message):
            return hacked_message, hacked_key
    raise ValueError(f"Error hacking message! {hacked_message} {message}")


def diffie_helman_mitm_attack(bot_a: DiffieHelmanBot, bot_b: DiffieHelmanBot, message_a: str, message_b: str) -> None:
    public_a = bot_a.get_public_key()
    bot_a_p = bot_a._p
    bot_a_g = bot_a._g

    public_b = bot_b.get_public_key()
    bot_b_p = bot_b._p
    bot_b_g = bot_b._g

    private_a = bot_a.get_private_key(bot_b_p)
    private_b = bot_b.get_private_key(bot_a_p)

    encrypted_message_a = bot_a.encrypt_message(message_a)
    _diffie_helman_decrypt(bot_a, encrypted_message_a, message_a)
    encrypted_message_b = bot_b.encrypt_message(message_b)
    _diffie_helman_decrypt(bot_b, encrypted_message_b, message_b)
