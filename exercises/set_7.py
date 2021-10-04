from typing import List, Optional

from exercises.const import DEFAULT_ENCODING
from exercises.set_1 import HEX_CHARS, hex_to_int, hex_to_text, int_to_hex, text_to_hex, process_repeating_xor
from exercises.set_2 import (
    encrypt_aes128_cbc,
    decrypt_aes128_cbc,
    kv_parser,
    find_key_block_size,
    cbc_find_prefix_len,
    kv_serializer,
)
from exercises.utils import gen_aes_key, pkcs7_pad

### Challenge 49
class Transaction:
    def __init__(self, to: str, amount: int):
        self._to = to
        self._amount = amount

    def __str__(self):
        return f"{self._to}:{self._amount}"


class CbcMacClient:
    def __init__(self, key: str, fixed_iv: Optional[str] = None):
        self._key = key
        self._block_size = len(key)
        self._iv = fixed_iv

    def sign(self, from_id: str, to_id: str, amount: int) -> str:
        iv = self._iv
        if not iv:
            iv = gen_aes_key().decode(DEFAULT_ENCODING)
        message_dict = {"from": str(from_id), "to": str(to_id), "amount": str(amount)}
        raw_message = kv_serializer(message_dict)
        encrypted_message = encrypt_aes128_cbc(raw_message, self._key, iv)
        mac = encrypted_message[-1 * self._block_size :]
        return raw_message + iv + mac

    def sign_many(self, from_id: str, transactions: List[Transaction]) -> str:
        iv = self._iv
        if not iv:
            iv = gen_aes_key().decode(DEFAULT_ENCODING)
        message_dict = {"from": str(from_id), "tx_list": ";".join(map(str, transactions))}
        raw_message = kv_serializer(message_dict)
        encrypted_message = encrypt_aes128_cbc(raw_message, self._key, iv)
        mac = encrypted_message[-1 * self._block_size :]
        return raw_message + mac


class CbcMacServer:
    def __init__(self, key: str, fixed_iv: Optional[str] = None):
        self._key = key
        self._block_size = len(key)
        self._iv = fixed_iv

    def validate(self, encrypted_message: str) -> bool:
        raw_message = encrypted_message[: -(16 * 2)]
        new_iv = encrypted_message[-(16 * 2) : -16]
        mac = encrypted_message[-16:]
        re_encrypted_message = encrypt_aes128_cbc(raw_message, self._key, new_iv)
        kvs = kv_parser(raw_message)

        if re_encrypted_message[-1 * 16 :] == mac:
            print(
                f"Processing payment from account {kvs['from']} to account {kvs['to']} for {kvs['amount']} spacebucks"
            )
            return True
        return False

    def validate_many(self, encrypted_message: str) -> bool:
        raw_message = encrypted_message[:-16]
        iv = self._iv
        mac = encrypted_message[-16:]
        re_encrypted_message = encrypt_aes128_cbc(raw_message, self._key, iv)

        if re_encrypted_message[-1 * 16 :] == mac:
            kvs = kv_parser(raw_message)
            transactions = kvs["tx_list"].split(";")
            print(f"Processing payments from account {kvs['from']} to {transactions}")
            return True
        return False


def forge_message_with_iv(message: str, target_account: str) -> str:
    raw_message = pkcs7_pad(message[: -(16 * 2)], 16)
    original_iv = message[-(16 * 2) : -16]
    mac = message[-16:]
    acct_len = len(target_account)
    new_message = raw_message[:5] + target_account + raw_message[6:]
    new_iv = (
        original_iv[:5]
        + process_repeating_xor(
            process_repeating_xor(target_account, raw_message[5 : 5 + acct_len]), original_iv[5 : 5 + acct_len]
        )
        + original_iv[5 + acct_len :]
    )
    return new_message + new_iv + mac


def forge_many_messages(client: CbcMacClient, message: str, target_tx: Transaction, target_account: str) -> str:
    original_message = message[:-16]
    original_mac = message[-16:]
    padded_message = pkcs7_pad(original_message, 16)
    new_signed = client.sign_many(target_tx._to, [Transaction(target_account, 0), target_tx])
    new_mac = new_signed[-16:]
    new_padded = pkcs7_pad(new_signed[16:-16], 16)
    new_message = padded_message + process_repeating_xor(new_signed[:16], original_mac) + new_padded
    return new_message + new_mac
