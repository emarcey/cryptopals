import base64
import os
import pytest
from random import choice
from typing import Dict

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import multiline_base64_to_plaintext, base64_to_plaintext
from exercises.set_2 import (
    byte_at_a_time_decryption,
    byte_at_a_time_decryption_with_prefix,
    decrypt_aes128_cbc,
    detect_ecb_or_cbc,
    encrypt_aes128_cbc,
    encrypt_ecb_or_cbc,
    find_key_block_size,
    find_prefix_size,
    hack_admin_user,
    kv_parser,
    kv_serializer,
    Oracle,
    PrefixOracle,
    profile_for,
    ProfileOracle,
    hack_admin_cbc,
    CBCProfileOracle,
)
from exercises.utils import gen_aes_key

play_that_text = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
yellow_submarine = "YELLOW SUBMARINE"


def test_decrypt_aes128_cbc() -> None:
    with open(f"{os.getcwd()}/data/set2_challenge9.txt", "r") as f:
        text = "".join([line.strip() for line in f])
        assert play_that_text == decrypt_aes128_cbc(base64_to_plaintext(text), yellow_submarine, "\x00" * 16)


def test_encrypt_aes128_cbc() -> None:
    x = encrypt_aes128_cbc(play_that_text, yellow_submarine, "\x00" * 16)
    assert play_that_text == decrypt_aes128_cbc(
        x,
        yellow_submarine,
        "\x00" * 16,
    )


def test_detect_ecb_or_cbc() -> None:
    for i in range(1000):
        text = gen_aes_key().decode(DEFAULT_ENCODING) * 10
        encrypted, enc_type = encrypt_ecb_or_cbc(text)
        assert enc_type == detect_ecb_or_cbc(encrypted)


def test_find_key_block_size() -> None:
    for i in range(1000):
        assert find_key_block_size(Oracle()) == 16


def test_byte_at_a_time_decryption() -> None:
    o = Oracle()
    assert (
        multiline_base64_to_plaintext(byte_at_a_time_decryption(o))
        == "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    )


@pytest.mark.parametrize(
    "given, expected",
    [("", {}), ("a=1", {"a": "1"}), ("foo=bar&baz=qux&zap=zazzle", {"foo": "bar", "baz": "qux", "zap": "zazzle"})],
)
def test_kv_parser(given: str, expected: Dict[str, str]) -> None:
    assert kv_parser(given) == expected


@pytest.mark.parametrize(
    "given, expected",
    [({}, ""), ({"a": "1"}, "a=1"), ({"foo": "bar", "baz": "qux", "zap": "zazzle"}, "foo=bar&baz=qux&zap=zazzle")],
)
def test_kv_serializer(given: str, expected: Dict[str, str]) -> None:
    assert kv_serializer(given) == expected


@pytest.mark.parametrize("given", [("abc1234"), ("abc&123=4")])
def test_profile_for(given: str) -> None:
    assert profile_for(given, 10) == "email=abc1234&uid=10&role=user"


def test_profile_encrypt_decrypt() -> None:
    profile = profile_for("evan@evan.email", 11)
    o = ProfileOracle()
    encrypted = o.encrypt("evan@evan.email", 11)
    assert o.decrypt(encrypted) == kv_parser(profile)


def test_hack_admin_user() -> None:
    assert hack_admin_user("evanmarcey@gmail.com") == {
        "email": "evanmarcey@gmail.com",
        "uid": "11111111111",
        "role": "admin",
    }


def test_find_prefix_size() -> None:
    for i in range(1000):
        p = PrefixOracle()
        block_size = find_key_block_size(p)
        assert find_prefix_size(p, block_size) == len(p._prefix_str)


def test_byte_at_a_time_decryption_with_prefix() -> None:
    for i in range(10):
        o = PrefixOracle()
        assert (
            multiline_base64_to_plaintext(byte_at_a_time_decryption_with_prefix(o))
            == "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
        )


def test_hack_admin_cbc() -> None:
    for i in range(10):
        o = CBCProfileOracle()
        tmp = o.encrypt(";admin;")
        assert "admin" not in o.get_kvs(tmp)
        result = hack_admin_cbc(o)
        assert result["admin"] == "true"
