import pytest
from exercises.utils import pkcs7_pad, pkcs7_unpad


@pytest.mark.parametrize(
    "given, given_block_size, expected",
    [
        ("", 16, "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
        ("a", 16, "a\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F"),
        ("ab", 16, "ab\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E"),
        ("abc", 16, "abc\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D"),
        ("abcd", 16, "abcd\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"),
        ("abcde", 16, "abcde\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"),
        ("abcdef", 16, "abcdef\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A"),
        ("abcdefg", 16, "abcdefg\x09\x09\x09\x09\x09\x09\x09\x09\x09"),
        ("abcdefgh", 16, "abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08"),
        ("abcdefghi", 16, "abcdefghi\x07\x07\x07\x07\x07\x07\x07"),
        ("abcdefghij", 16, "abcdefghij\x06\x06\x06\x06\x06\x06"),
        ("abcdefghijk", 16, "abcdefghijk\x05\x05\x05\x05\x05"),
        ("abcdefghijkl", 16, "abcdefghijkl\x04\x04\x04\x04"),
        ("abcdefghijklm", 16, "abcdefghijklm\x03\x03\x03"),
        ("abcdefghijklmn", 16, "abcdefghijklmn\x02\x02"),
        ("abcdefghijklmno", 16, "abcdefghijklmno\x01"),
        ("abcdefghijklmnop", 16, "abcdefghijklmnop"),
        ("YELLOW SUBMARINE", 20, "YELLOW SUBMARINE\x04\x04\x04\x04"),
    ],
)
def test_pkcs7_unad(given: str, given_block_size: int, expected: str) -> None:
    assert pkcs7_pad(given, given_block_size) == expected


@pytest.mark.parametrize(
    "given, expected",
    [
        ("", ""),
        ("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", ""),
        ("a\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F", "a"),
        ("ab\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E", "ab"),
        ("abc\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D", "abc"),
        ("abcd\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C", "abcd"),
        ("abcde\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B", "abcde"),
        ("abcdef\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A", "abcdef"),
        ("abcdefg\x09\x09\x09\x09\x09\x09\x09\x09\x09", "abcdefg"),
        ("abcdefgh\x08\x08\x08\x08\x08\x08\x08\x08", "abcdefgh"),
        ("abcdefghi\x07\x07\x07\x07\x07\x07\x07", "abcdefghi"),
        ("abcdefghij\x06\x06\x06\x06\x06\x06", "abcdefghij"),
        ("abcdefghijk\x05\x05\x05\x05\x05", "abcdefghijk"),
        ("abcdefghijkl\x04\x04\x04\x04", "abcdefghijkl"),
        ("abcdefghijklm\x03\x03\x03", "abcdefghijklm"),
        ("abcdefghijklmn\x02\x02", "abcdefghijklmn"),
        ("abcdefghijklmno\x01", "abcdefghijklmno"),
        ("abcdefghijklmnop", "abcdefghijklmnop"),
        ("YELLOW SUBMARINE\x04\x04\x04\x04", "YELLOW SUBMARINE"),
    ],
)
def test_pkcs7_pad(given: str, expected: str) -> None:
    assert pkcs7_unpad(given) == expected
