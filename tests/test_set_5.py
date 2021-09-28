import pytest
from secrets import choice, randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING, STARTER_SAFE_PRIMES, SMALL_PASSWORD_DICT
from exercises.set_5 import (
    _g_equals_1,
    _g_equals_p,
    _g_equals_p_minus_1,
    break_srp,
    diffie_helman,
    diffie_helman_mitm_attack,
    diffie_helman_mitm_attack_adj_g,
    DiffieHelmanBot,
    invmod,
    srp,
    SrpClient,
    SrpServer,
    simple_srp,
    SimpleSrpClient,
    SimpleSrpServer,
    simple_srp_dictionary_attack,
    rsa,
    encrypt_rsa_int,
    decrypt_rsa_int,
    encrypt_rsa,
    hack_rsa,
    decrypt_rsa,
)
from exercises.utils import gen_aes_key


@pytest.mark.parametrize(
    "given_p, given_g",
    [
        (37, 5),
        (
            0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
            2,
        ),
    ],
)
def test_diffie_helman(given_p: int, given_g: int) -> None:
    assert diffie_helman(given_p, given_g)


@pytest.mark.parametrize(
    "given_p, given_g",
    [
        (37, 5),
        (
            0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
            2,
        ),
    ],
)
def test_diffie_helman_bot(given_p: int, given_g: int) -> None:
    bot1 = DiffieHelmanBot(given_p, given_g)
    bot2 = DiffieHelmanBot(given_p, given_g)
    pub1 = bot1.get_public_key()
    pub2 = bot2.get_public_key()
    assert bot1.get_private_key(pub2) == bot2.get_private_key(pub1)


@pytest.mark.parametrize("execution_number", range(50))
def test_diffie_helman_mitm_attack(execution_number: int) -> None:
    bot_a = DiffieHelmanBot()
    bot_b = DiffieHelmanBot()
    message_a = "Hi, how are you?"
    message_b = "Well, and you?"
    diffie_helman_mitm_attack(bot_a, bot_b, message_a, message_b)


@pytest.mark.parametrize("execution_number", range(50))
def test_diffie_helman_mitm_attack_adj_g(execution_number: int) -> None:
    bot_a = DiffieHelmanBot()
    bot_b = DiffieHelmanBot()
    message = "Hi, how are you?"
    f = choice([_g_equals_p, _g_equals_1, _g_equals_p_minus_1])
    diffie_helman_mitm_attack_adj_g(bot_a, bot_b, f, message)


@pytest.mark.parametrize("execution_number", range(10))
def test_srp(execution_number: int) -> None:
    i = "evanmarcey@gmail.com"
    p = gen_aes_key().decode(DEFAULT_ENCODING)
    n = choice(STARTER_SAFE_PRIMES)
    client = SrpClient(i, p, n)
    server = SrpServer(i, p, n)
    srp(client, server)


@pytest.mark.parametrize("execution_number", range(10))
def test_break_srp(execution_number: int) -> None:
    i = "evanmarcey@gmail.com"
    p = gen_aes_key().decode(DEFAULT_ENCODING)
    n = choice(STARTER_SAFE_PRIMES)
    client = SrpClient(i, p, n)
    server = SrpServer(i, p, n)
    a_override = choice([0, n, n * 2])
    break_srp(client, server, a_override)


@pytest.mark.parametrize("execution_number", range(10))
def test_simple_srp(execution_number: int) -> None:
    i = "evanmarcey@gmail.com"
    p = gen_aes_key().decode(DEFAULT_ENCODING)
    n = choice(STARTER_SAFE_PRIMES)
    client = SimpleSrpClient(i, p, n)
    server = SimpleSrpServer(i, n)
    simple_srp(client, server)


@pytest.mark.parametrize("execution_number", range(10))
def test_simple_srp_dictionary_attack(execution_number: int) -> None:
    p = choice(SMALL_PASSWORD_DICT)
    i = "evanmarcey@gmail.com"
    n = choice(STARTER_SAFE_PRIMES)

    client = SimpleSrpClient(i, p, n)
    server = SimpleSrpServer(i, n)
    assert p in simple_srp_dictionary_attack(client, server)


@pytest.mark.parametrize(
    "given_a, given_b, expected",
    [(123, 4567, 854), (854, 4567, 123), (0, 1, 0), (1, 2, 1), (11, 6, 5), (5, 6, 5), (17, 3120, 2753)],
)
def test_invmod(given_a: int, given_b: int, expected: int) -> None:
    assert invmod(given_a, given_b) == expected


@pytest.mark.parametrize("execution_number", range(10))
def test_rsa(execution_number: int) -> None:
    m = "Hello"
    public_key, private_key = rsa(prime_length=1024)
    assert decrypt_rsa(encrypt_rsa(m, public_key), private_key) == m


@pytest.mark.parametrize("execution_number", range(5))
def test_hack_rsa(execution_number: int) -> None:
    messages = []
    m = token_bytes(randbelow(128) + 16).decode(DEFAULT_ENCODING)
    for i in range(3):
        public_key, private_key = rsa(prime_length=1024)
        c = encrypt_rsa(m, public_key)
        messages.append((c, public_key))

    assert hack_rsa(messages) == m
