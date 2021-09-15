import os
import pytest

from exercises.set_1 import (
    calculate_hamming_distance,
    find_record_with_xor_char,
    find_xor_char,
    hex_to_base64,
    hex_xor,
    text_to_hex_repeating_key,
)


@pytest.mark.parametrize(
    "given, expected",
    [
        ("00", "AA=="),
        ("0000", "AAA="),
        (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        ),
    ],
)
def test_hex_to_base64(given: str, expected: str) -> None:
    assert hex_to_base64(given) == expected


@pytest.mark.parametrize(
    "given1, given2, expected",
    [
        ("0", "0", "0"),
        ("1", "0", "1"),
        ("1", "2", "3"),
        (
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
            "746865206b696420646f6e277420706c6179",
        ),
    ],
)
def test_hex_to_base64(given1: str, given2: str, expected: str) -> None:
    assert hex_xor(given1, given2) == expected


def test_find_xor_char() -> None:
    assert (
        find_xor_char("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0]
        == "Cooking MC's like a pound of bacon"
    )


def test_find_xor_char() -> None:
    assert (
        find_xor_char("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0]
        == "Cooking MC's like a pound of bacon"
    )


def test_find_record_with_xor_char() -> None:
    assert find_record_with_xor_char(f"{os.getcwd()}/data/set1_challenge4.txt") == (
        "170",
        "Now that the party is jumping",
        27,
        "5",
    )


def test_text_to_hex_repeating_key() -> None:
    text = """Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""
    assert (
        text_to_hex_repeating_key(text, "ICE")
        == """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""
    )


@pytest.mark.parametrize(
    "given1, given2, expected",
    [
        ("1", "1", 0),
        ("t", "w", 2),
        (
            "this is a test",
            "wokka wokka!!!",
            37,
        ),
    ],
)
def test_calculate_hamming_distance(given1: str, given2: str, expected: int) -> None:
    assert calculate_hamming_distance(given1, given2) == expected
