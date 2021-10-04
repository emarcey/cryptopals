import pytest

from exercises.set_7 import CbcMacClient, CbcMacServer, forge_message_with_iv, Transaction, forge_many_messages
from exercises.utils import gen_aes_key


@pytest.mark.parametrize("execution_number", range(5))
def test_forge_message_with_iv(execution_number: int) -> None:
    k = gen_aes_key()
    client = CbcMacClient(k)
    server = CbcMacServer(k)
    initial_msg = client.sign("1", "1", 1000000)
    forged_msg = forge_message_with_iv(initial_msg, "7")
    assert server.validate(forged_msg)


@pytest.mark.parametrize("execution_number", range(5))
def test_sign_many(execution_number: int) -> None:
    k = gen_aes_key()
    iv = "\x00" * 16
    transactions = [Transaction("abc", 1), Transaction("def", 1)]
    client = CbcMacClient(k, fixed_iv=iv)
    server = CbcMacServer(k, fixed_iv=iv)
    initial_msg = client.sign_many("1", transactions)
    assert server.validate_many(initial_msg)


@pytest.mark.parametrize("execution_number", range(5))
def test_forge_many(execution_number: int) -> None:
    iv = "\x00" * 16
    k = gen_aes_key()
    client = CbcMacClient(k, fixed_iv=iv)
    server = CbcMacServer(k, fixed_iv=iv)
    transactions = [Transaction("abc", 1), Transaction("def", 1)]
    initial_msg = client.sign_many("12345", transactions)
    forged_msg = forge_many_messages(client, initial_msg, Transaction("de", 1000000), "12345")
    assert server.validate_many(forged_msg)
