import pytest
from secrets import randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.set_5 import diffie_helman, DiffieHelmanBot, diffie_helman_mitm_attack


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
