import pytest

from exercises.set_7 import CbcMacClient, CbcMacServer, forge_messsage_with_iv
from exercises.utils import gen_aes_key


@pytest.mark.parametrize("execution_number", range(5))
def test_forge_messsage_with_iv(execution_number: int) -> None:
    k = gen_aes_key()
    client = CbcMacClient(k)
    server = CbcMacServer(k)
    initial_msg = client.sign("1", "1", 1000000)
    forged_msg = forge_messsage_with_iv(initial_msg, "7")
    assert server.validate(forged_msg)
