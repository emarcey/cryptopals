import os
import pytest
from secrets import choice, randbelow, token_bytes

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import int_to_hex, base64_to_plaintext
from exercises.set_4 import sha1
from exercises.set_5 import rsa, encrypt_rsa
from exercises.set_6 import (
    brute_force_recover_dsa_private_key,
    decrypt_even_odd_oracle,
    dsa,
    DsaSignature,
    DsaSignatureOracle,
    DsaSignedMessage,
    EvenOddRsaOracle,
    find_paired_messages,
    forge_dsa_signature,
    forge_rsa_signature,
    DEFAULT_P,
    RsaSignatureOracle,
    recover_dsa_private_key,
    unpadded_rsa_oracle_attack,
    UnpaddedRsaOracle,
)
from exercises.utils import str_to_chunks


@pytest.mark.parametrize("execution_number", range(5))
def test_unpadded_rsa_oracle_attack(execution_number: int) -> None:
    public_key, private_key = rsa(prime_length=512)
    oracle = UnpaddedRsaOracle(private_key)
    message = "Hello there, friendo"
    encrypted = encrypt_rsa(message, public_key)
    decrypted = oracle.decrypt(encrypted)
    with pytest.raises(ValueError):
        decrypted = oracle.decrypt(encrypted)

    found = False
    for i in range(5):
        hacked_result = unpadded_rsa_oracle_attack(oracle, public_key, encrypted)
        if message == hacked_result:
            found = True
            break
    if not found:
        raise ValueError("Could not break")


@pytest.mark.parametrize("execution_number", range(5))
def test_rsa_signature_oracle(execution_number: int) -> None:
    m = "Hi mom"
    key_len = 1024
    public_key1, private_key1 = rsa(prime_length=key_len // 2)
    public_key2, private_key2 = rsa(prime_length=key_len // 2)
    oracle1 = RsaSignatureOracle(key_len, private_key1, public_key2)
    oracle2 = RsaSignatureOracle(key_len, private_key2, public_key1)
    encrypted_signature1 = oracle1.sign(m)
    assert oracle2.validate(encrypted_signature1, m)
    encrypted_signature2 = oracle2.sign(m)
    assert oracle1.validate(encrypted_signature2, m)


@pytest.mark.parametrize("execution_number", range(5))
def test_forge_rsa_signature(execution_number: int) -> None:
    m = "Hi mom"
    key_len = 1024
    public_key1, private_key1 = rsa(prime_length=key_len // 2)
    public_key2, private_key2 = rsa(prime_length=key_len // 2)
    oracle = RsaSignatureOracle(key_len, private_key1, public_key2)
    forged_signature = forge_rsa_signature(m, key_len)
    assert oracle.validate(forged_signature, m)


@pytest.mark.parametrize("execution_number", range(5))
def test_dsa_signature_oracle(execution_number: int) -> None:
    m = "Hi mom"
    private_key1, public_key1 = dsa()
    private_key2, public_key2 = dsa()
    oracle1 = DsaSignatureOracle(private_key1, public_key2)
    oracle2 = DsaSignatureOracle(private_key2, public_key1)
    encrypted_signature1 = oracle1.sign(m)
    assert oracle2.validate(encrypted_signature1, m)
    encrypted_signature2 = oracle2.sign(m)
    assert oracle1.validate(encrypted_signature2, m)


@pytest.mark.parametrize("execution_number", range(5))
def test_recover_dsa_private_key(execution_number: int) -> None:
    m = "Hi mom"
    private_key, public_key = dsa()
    oracle = DsaSignatureOracle(private_key, public_key)
    encrypted_signature = oracle.sign(m)
    assert recover_dsa_private_key(encrypted_signature, m, oracle._k) == private_key


def test_brute_force_recover_dsa_private_key() -> None:
    public_key = 0x84AD4719D044495496A3201C8FF484FEB45B962E7302E56A392AEE4ABAB3E4BDEBF2955B4736012F21A08084056B19BCD7FEE56048E004E44984E2F411788EFDC837A0D2E5ABB7B555039FD243AC01F0FB2ED1DEC568280CE678E931868D23EB095FDE9D3779191B8C0299D6E07BBB283E6633451E535C45513B2D33C99EA17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    signature = DsaSignature(r, s)
    m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    private_key = brute_force_recover_dsa_private_key(public_key, signature, m)
    assert sha1(int_to_hex(private_key)) == "0954edd5e0afe5542a4adf012611a91912a3ec16"


def test_find_paired_messages() -> None:
    public_key = 0x2D026F4BF30195EDE3A088DA85E398EF869611D0F68F0713D51C9C1A3A26C95105D915E2D8CDF26D056B86B8A7B85519B1C23CC3ECDC6062650462E3063BD179C2A6581519F674A61F1D89A1FFF27171EBC1B93D4DC57BCEB7AE2430F98A6A4D83D8279EE65D71C1203D2C96D65EBBF7CCE9D32971C3DE5084CCE04A2E147821
    with open(f"{os.getcwd()}/data/set6_challenge44.txt") as f:
        texts = [line.strip() for line in f]

    messages = []
    for chunk in str_to_chunks(texts, 4):
        msg = chunk[0].strip("msg: ").strip() + " "
        s = int(chunk[1].strip("s: "))
        r = int(chunk[2].strip("r: "))
        messages.append(DsaSignedMessage(msg, r, s))

    results = find_paired_messages(public_key, messages)
    assert len(results) == 1
    private_key = list(results)[0]
    assert sha1(int_to_hex(private_key)) == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    assert len(results[private_key]) == 5


@pytest.mark.parametrize("given", [("Hello, world"), ("Goodbye, world")])
def test_forge_dsa_signature(given: str) -> None:
    private_key, public_key = dsa(p=DEFAULT_P, g=DEFAULT_P + 1)
    forged_signature = forge_dsa_signature(public_key, given)
    oracle = DsaSignatureOracle(private_key, public_key, g=DEFAULT_P + 1)
    assert oracle.validate(forged_signature, given)


def test_decrypt_even_odd_oracle() -> None:
    public_key, private_key = rsa(prime_length=512)
    oracle = EvenOddRsaOracle(private_key)
    message = base64_to_plaintext(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    )
    ciphertext = encrypt_rsa(message, public_key)
    assert decrypt_even_odd_oracle(oracle, ciphertext, public_key) == message
