from Crypto.Util.number import getPrime
import hashlib
from secrets import randbelow
from typing import Callable, List, Optional, Tuple

from exercises.const import DEFAULT_ENCODING, SMALL_PASSWORD_DICT
from exercises.set_1 import hex_to_text, process_repeating_xor, int_to_hex, text_to_hex, hex_to_int
from exercises.set_2 import decrypt_aes128_cbc, encrypt_aes128_cbc
from exercises.set_4 import sha1
from exercises.utils import gen_aes_key, pkcs7_unpad

# Challenge 33
# https://rosettacode.org/wiki/Modular_exponentiation#Python
# https://en.wikipedia.org/wiki/Modular_exponentiation
def mod_exp(b: int, e: int, m: int) -> int:
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
    public_A = mod_exp(g, a, p)
    b = randbelow(p)
    public_B = mod_exp(g, b, p)
    private_key = mod_exp(public_B, a, p)
    private_key2 = mod_exp(public_A, b, p)
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
        return mod_exp(self._g, self._a, self._p)

    def get_private_key(self, public_key: int) -> str:
        if not self._private_key:
            self._private_key = mod_exp(public_key, self._a, self._p)
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


### Challenge 36
class SrpClient:
    def __init__(self, i: str, p: str, n: int, g: int = 2, k: int = 3):
        self._i = i
        self._p = p
        self._n = n
        self._g = g
        self._k = k

    def generate_a(self) -> Tuple[str, int]:
        self._a = randbelow(self._n)
        self.A = mod_exp(self._g, self._a, self._n)
        return self._i, self.A

    def calculate_u(self, s: int, B: int) -> None:
        self._s = s
        self.B = B
        uH = hashlib.sha256((str(self.A) + str(self.B)).encode(DEFAULT_ENCODING)).hexdigest()
        self._u = int(uH, 16)

    def generate_k(self) -> None:
        xH = hashlib.sha256((str(self._s) + self._p).encode(DEFAULT_ENCODING)).hexdigest()
        x = int(xH, 16)
        S = mod_exp(self.B - self._k * mod_exp(self._g, x, self._n), self._a + self._u * x, self._n)
        self.S = S
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
        v = mod_exp(self._g, x, self._n)
        self._s = s
        self._v = v

    def generate_b(self, i: str, A: int) -> Tuple[int, int]:
        self.A = A
        self._b = randbelow(self._n)
        self.B = self._k * self._v + mod_exp(self._g, self._b, self._n)
        return self._s, self.B

    def calculate_u(self) -> None:
        uH = hashlib.sha256((str(self.A) + str(self.B)).encode(DEFAULT_ENCODING)).hexdigest()
        self._u = int(uH, 16)

    def generate_k(self) -> None:
        S = mod_exp(self.A * mod_exp(self._v, self._u, self._n), self._b, self._n)
        self.S = S
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
        raise ValueError("Server unable to validate Client HMAC")
    return


### Challenge 37
def break_srp(client: SrpClient, server: SrpServer, a_override: int):
    i, A = client.generate_a()
    s, B = server.generate_b(i, a_override)
    client.calculate_u(s, B)
    server.calculate_u()
    client.generate_k()
    server.generate_k()

    fake_client_k = hashlib.sha256(str(0).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)
    fake_hmac = hmac_sha256(fake_client_k, str(s).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)
    if not server.validate_hmac(fake_hmac):
        raise ValueError("Server unable to validate Client HMAC")
    return


### Challenge 38
class SimpleSrpClient:
    def __init__(self, i: str, p: str, n: int, g: int = 2, k: int = 3):
        self._i = i
        self._p = p
        self._n = n
        self._g = g
        self._k = k

    def generate_a(self) -> Tuple[str, str, int]:
        self._a = randbelow(self._n)
        self.A = mod_exp(self._g, self._a, self._n)
        return self._i, self._p, self.A

    def generate_k(self, s: int, u: int, B: int) -> None:
        self._s = s
        self._u = u
        self.B = B
        xH = hashlib.sha256((str(self._s) + self._p).encode(DEFAULT_ENCODING)).hexdigest()
        x = int(xH, 16)
        S = mod_exp(self.B, self._a + self._u * x, self._n)
        self.S = S
        self.K = hashlib.sha256(str(S).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)

    def generate_hmac(self) -> str:
        return hmac_sha256(self.K, str(self._s).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)


class SimpleSrpServer:
    def __init__(self, i: str, n: int, g: int = 2, k: int = 3):
        self._i = i
        self._n = n
        self._g = g
        self._k = k

    def _gen_password_verifier(self, p: str):
        s = randbelow(64)
        xH = hashlib.sha256((str(s) + p).encode(DEFAULT_ENCODING)).hexdigest()
        x = int(xH, 16)
        v = mod_exp(self._g, x, self._n)
        self._s = s
        self._v = v

    def generate_b(self, i: str, p: str, A: int) -> Tuple[int, int, int]:
        self._gen_password_verifier(p)
        self.A = A
        self._b = randbelow(self._n)
        self.B = mod_exp(self._g, self._b, self._n)
        self._u = randbelow(2 ** 128)
        return self._s, self.B, self._u

    def generate_k(self) -> None:
        S = mod_exp(self.A * mod_exp(self._v, self._u, self._n), self._b, self._n)
        self.S = S
        self.K = hashlib.sha256(str(S).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)

    def validate_hmac(self, client_hmac: str) -> bool:
        server_hmac = hmac_sha256(self.K, str(self._s).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)
        return server_hmac == client_hmac


def simple_srp(client: SimpleSrpClient, server: SimpleSrpServer):
    i, p, A = client.generate_a()
    s, B, u = server.generate_b(i, p, A)
    client.generate_k(s, u, B)
    server.generate_k()
    client_hmac = client.generate_hmac()
    if not server.validate_hmac(client_hmac):
        raise ValueError("Server unable to validate Client HMAC")
    return


def simple_srp_dictionary_attack(client: SrpClient, server: SrpServer) -> List[str]:
    i, p, A = client.generate_a()
    s, B, u = server.generate_b(i, p, A)
    client.generate_k(s, u, B)
    server.generate_k()
    client_hmac = client.generate_hmac()

    valid_candidates = []
    for candidate in SMALL_PASSWORD_DICT:
        forged_xH = hashlib.sha256((str(s) + candidate).encode(DEFAULT_ENCODING)).hexdigest()
        forged_x = int(forged_xH, 16)
        forged_v = mod_exp(server._g, forged_x, server._n)
        forged_S = mod_exp(A * mod_exp(forged_v, u, server._n), server._b, server._n)
        forged_K = hashlib.sha256(str(forged_S).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)
        forged_hmac = hmac_sha256(forged_K, str(s).encode(DEFAULT_ENCODING)).digest().decode(DEFAULT_ENCODING)
        if client_hmac == forged_hmac and server.validate_hmac(forged_hmac):
            valid_candidates.append(candidate)

    if not valid_candidates:
        raise ValueError("Could not find a password candidate")

    return valid_candidates


### Challenge 39
class RsaKey:
    def __init__(self, v: int, n: int):
        self.v = v
        self.n = n


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    r1 = a
    r2 = b
    u1 = 1
    u2 = 0
    v1 = 0
    v2 = 1

    while r2 != 0:
        q = r1 // r2
        r3 = r1
        u3 = u1
        v3 = v1
        r1 = r2
        u1 = u2
        v1 = v2
        r2 = r3 - q * r2
        u2 = u3 - q * u2
        v2 = v3 - q * v2

    return r1, u1, v1


def invmod(a: int, b: int) -> int:
    r, u, v = extended_gcd(a, b)
    return u % b


def lcm(a, b):
    """Computes the lowest common multiple between a and b using the GCD method."""
    return a // extended_gcd(a, b)[0] * b


def rsa(e: int = 3, prime_length: int = 16) -> Tuple[RsaKey, RsaKey]:
    et = 0
    while extended_gcd(e, et)[0] != 1:
        p = getPrime(prime_length)
        q = getPrime(prime_length)
        n = p * q
        et = lcm(p - 1, q - 1)

    d = invmod(e, et)
    public = RsaKey(e, n)
    private = RsaKey(d, n)
    return public, private


def encrypt_rsa_int(m: int, e: int, n: int) -> int:
    return mod_exp(m, e, n)


def decrypt_rsa_int(c: int, d: int, n: int) -> int:
    return mod_exp(c, d, n)


def encrypt_rsa(m: str, k: RsaKey) -> int:
    m_int = hex_to_int(text_to_hex(m))
    return encrypt_rsa_int(m_int, k.v, k.n)


def decrypt_rsa(c: int, k: RsaKey) -> int:
    m_int = decrypt_rsa_int(c, k.v, k.n)
    hex_val = int_to_hex(m_int)
    if len(hex_val) % 2 == 1:
        hex_val = "0" + hex_val
    return hex_to_text(hex_val)


### Challenge 40
def find_n_root(x: int, n: int) -> int:
    # https://stackoverflow.com/q/55436001
    low = 0
    high = x
    while low < high:
        mid = (low + high) // 2
        if mid ** n < x:
            low = mid + 1
            continue
        high = mid

    return mid


def hack_rsa(messages: List[Tuple[str, RsaKey]]) -> str:
    if len(messages) != 3:
        raise ValueError(f"Invalid number of messages: {len(messages)}. Expected: 3")

    product_n = 1
    for message in messages:
        product_n *= message[1].n

    total = 0
    for message in messages:
        m_s = product_n // message[1].n
        total += message[0] * m_s * invmod(m_s, message[1].n)

    return hex_to_text(int_to_hex(find_n_root(total % product_n, 3)))
