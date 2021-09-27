import hashlib
from secrets import randbelow
from typing import Callable, List, Optional, Tuple

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import hex_to_text, process_repeating_xor
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


def _diffie_helman_decrypt(
    bot: DiffieHelmanBot, encrypted_message: str, message: str, idx_vals: Optional[List[int]] = None
) -> Tuple[str, str]:
    if not idx_vals:
        idx_vals = range(2)
    for i in idx_vals:
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

    bot_a.get_private_key(bot_b_p)
    bot_b.get_private_key(bot_a_p)

    encrypted_message_a = bot_a.encrypt_message(message_a)
    _diffie_helman_decrypt(bot_a, encrypted_message_a, message_a)
    encrypted_message_b = bot_b.encrypt_message(message_b)
    _diffie_helman_decrypt(bot_b, encrypted_message_b, message_b)


### Challenge 35
# g = 1 => private = 1
# g = p => private = 0
# g = p - 1 => private = 1 or p - 1
def _g_equals_1(p: int) -> int:
    return 1


def _g_equals_p(p: int) -> int:
    return p


def _g_equals_p_minus_1(p: int) -> int:
    return p - 1


def diffie_helman_mitm_attack_adj_g(
    bot_a: DiffieHelmanBot, bot_b: DiffieHelmanBot, g_func: Callable, message: str
) -> None:
    bot_b._g = g_func(bot_a._p)
    public_a = bot_a.get_public_key()
    public_b = bot_b.get_public_key()

    bot_a.get_private_key(public_b)
    bot_b.get_private_key(public_a)

    encrypted_message = bot_a.encrypt_message(message)
    _diffie_helman_decrypt(bot_a, encrypted_message, message, [0, 1, bot_a._p - 1])


def hmac_sha256(key: str, message: str) -> str:
    block_size = 64
    output_size = 20

    if len(key) > block_size:
        key = hashlib.sha256(key.encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)

    if len(key) < 64:
        key += "\x00" * (64 - len(key))

    o_key_pad = process_repeating_xor("\x5c" * 64, key).encode(DEFAULT_ENCODING)
    i_key_pad = process_repeating_xor("\x36" * 64, key).encode(DEFAULT_ENCODING)

    return hashlib.sha256(o_key_pad + hashlib.sha256(i_key_pad + message).digest())


class SrpClient:
    def __init__(self, i: str, p: str, n: int, g: int = 2, k: int = 3):
        self._i = i
        self._p = p
        self._n = n
        self._g = g
        self._k = k

    def generate_a(self) -> Tuple[str, int]:
        self._a = randbelow(self._n)
        self.A = _mod_exp(self._g, self._a, self._n)
        return self._i, self.A

    def calculate_u(self, s: int, B: int) -> None:
        self._s = s
        self.B = B
        uH = hashlib.sha256((str(self.A) + str(self.B)).encode(DEFAULT_ENCODING)).hexdigest()
        self.u = int(uH, 16)

    def generate_k(self) -> None:
        xH = hashlib.sha256((str(self._s) + self._p).encode(DEFAULT_ENCODING)).hexdigest()
        x = int(xH, 16)
        S = _mod_exp(self.B - self._k * _mod_exp(self._g, x, self._n), self._a + self.u * x, self._n)
        self.K = hashlib.sha256(str(S).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)

    def generate_hmac(self) -> str:
        return hmac_sha256(self.K, str(self._s).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)


class SrpServer:
    def __init__(self, i: str, p: str, n: int, g: int = 2, k: int = 3):
        self._i = i
        self._p = p
        self._n = n
        self._g = g
        self._k = k

        self._gen_password_verifier()

    def _gen_password_verifier(self):
        s = randbelow(64)
        xH = hashlib.sha256((str(s) + self._p).encode(DEFAULT_ENCODING)).hexdigest()
        x = int(xH, 16)
        v = _mod_exp(self._g, x, self._n)
        self._s = s
        self._v = v

    def generate_b(self, i: str, A: int) -> Tuple[int, int]:
        self.A = A
        self._b = randbelow(self._n)
        self.B = self._k * self._v + _mod_exp(self._g, self._b, self._n)
        return self._s, self.B

    def calculate_u(self) -> None:
        uH = hashlib.sha256((str(self.A) + str(self.B)).encode(DEFAULT_ENCODING)).hexdigest()
        self._u = int(uH, 16)

    def generate_k(self) -> None:
        S = _mod_exp(self.A * _mod_exp(self._v, self._u, self._n), self._b, self._n)
        self.K = hashlib.sha256(str(S).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)

    def validate_hmac(self, client_hmac: str) -> bool:
        server_hmac = hmac_sha256(self.K, str(self._s).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)
        return server_hmac == client_hmac


def srp(client: SrpClient, server: SrpServer):
    i, A = client.generate_a()
    s, B = server.generate_b(i, A)
    client.calculate_u(s, B)
    server.calculate_u()
    client.generate_k()
    server.generate_k()
    client_hmac = client.generate_hmac()
    if not server.validate_hmac(client_hmac):
        raise ValueError("Server to validate Client HMAC")
    return
