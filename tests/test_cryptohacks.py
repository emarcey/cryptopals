from exercises.const import DEFAULT_ENCODING
from exercises.utils import gen_aes_key
from exercises.cryptohacks import (
    bytes2matrix,
    matrix2bytes,
    add_round_key,
    sub_bytes,
    inv_mix_columns,
    inv_shift_rows,
    aes_decrypt,
    s_box,
    inv_s_box,
    aes_password_brute_force,
)


def test_bytes2matrix():
    matrix = [
        [99, 114, 121, 112],
        [116, 111, 123, 105],
        [110, 109, 97, 116],
        [114, 105, 120, 125],
    ]
    msg = "crypto{inmatrix}"

    assert bytes2matrix(msg) == matrix


def test_matrix2bytes():
    matrix = [
        [99, 114, 121, 112],
        [116, 111, 123, 105],
        [110, 109, 97, 116],
        [114, 105, 120, 125],
    ]
    msg = "crypto{inmatrix}"

    assert matrix2bytes(matrix) == msg


def test_add_round_key():
    state = [
        [206, 243, 61, 34],
        [171, 11, 93, 31],
        [16, 200, 91, 108],
        [150, 3, 194, 51],
    ]

    round_key = [
        [173, 129, 68, 82],
        [223, 100, 38, 109],
        [32, 189, 53, 8],
        [253, 48, 187, 78],
    ]

    msg = "crypto{r0undk3y}"
    assert matrix2bytes(add_round_key(state, round_key)) == msg


def test_sub_bytes():

    state = [
        [251, 64, 182, 81],
        [146, 168, 33, 80],
        [199, 159, 195, 24],
        [64, 80, 182, 255],
    ]
    msg = "crypto{l1n34rly}"
    assert matrix2bytes(sub_bytes(state, inv_s_box)) == msg


def test_inv_shift_rows():
    state = [
        [108, 106, 71, 86],
        [96, 62, 38, 72],
        [42, 184, 92, 209],
        [94, 79, 8, 54],
    ]
    msg = "crypto{d1ffUs3R}"
    inv_mix_columns(state)
    inv_shift_rows(state)
    assert matrix2bytes(state) == msg


def test_aes_decrypt():
    N_ROUNDS = 10

    key = b"\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\"
    ciphertext = b"\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd"
    msg = "crypto{MYAES128}"
    assert aes_decrypt(key, ciphertext, inv_s_box, N_ROUNDS) == msg


def test_aes_password_brute_force():
    ciphertext = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"
    msg = "crypto{k3y5__r__n07__p455w0rdz?}"
    assert aes_password_brute_force(ciphertext)[0].decode(DEFAULT_ENCODING) == msg
