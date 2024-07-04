"""
Speck Cipher

Implementation from: https://eprint.iacr.org/2013/404.pdf
"""

import numpy as np

from ciphers.utils import common


# ---------------------- CONSTANTS -------------------------
ALLOWED_CONFIG = {
    "64/96": (np.uint32, 32, 3, 2), 
}
"""
Allowed configurations of the cipher.
Each configuration is identified by a name and is associated with
a tuple containing: word type, word size in bit, key size in number of words and
plaintext size in number of words. 
"""

WORDSIZE_TO_ALPHABETA = {
    16: (7, 2),
    24: (8, 3),
    32: (8, 3),
    48: (8, 3),
    64: (8, 3)
}
"""
"""


# ---------------------- FUNCTIONS -------------------------
def encrypt_function(
        plaintexts: np.ndarray,
        keys: np.ndarray,
        word_size: int) -> None:
    """
    """
    alpha, beta = WORDSIZE_TO_ALPHABETA[word_size]
    mask = common.get_mask(word_size)
    plaintexts[:, 0] = common.rotate_right(alpha, plaintexts[:, 0], word_size)
    plaintexts[:, 0] = (plaintexts[:, 0] + plaintexts[:, 1]) & mask
    plaintexts[:, 0] ^= keys
    plaintexts[:, 1] = common.rotate_left(beta, plaintexts[:, 1], word_size)
    plaintexts[:, 1] ^= plaintexts[:, 0]


def update_keys(
        keys: np.ndarray,
        round_number: int,
        word_size: int) -> None:
    """
    """
    number_of_kwords = keys.shape[1]
    encrypt_function(keys[:, (number_of_kwords-2):number_of_kwords], round_number, word_size)
    temp = keys[:, number_of_kwords - 2].copy()
    for i in reversed(range(1, number_of_kwords - 1)):
        keys[:, i] = keys[:, i - 1]
    keys[:, 0] = temp


def encrypt(
        plaintexts: np.ndarray,
        keys: np.ndarray,
        current_round: int,
        number_of_rounds: int,
        word_size: int) -> None:
    """
    """
    for round_number in range(current_round, current_round+number_of_rounds):
        encrypt_function(plaintexts, keys[:, -1], word_size)
        update_keys(keys, round_number, word_size)


def decrypt_function(
        ciphertexts: np.ndarray,
        keys: np.ndarray,
        word_size: int) -> None:
    """
    """
    alpha, beta = WORDSIZE_TO_ALPHABETA[word_size]
    mask = common.get_mask(word_size)
    ciphertexts[:, 1] ^= ciphertexts[:, 0]
    ciphertexts[:, 1] = common.rotate_right(beta, ciphertexts[:, 1], word_size)
    ciphertexts[:, 0] ^= keys
    ciphertexts[:, 0] = (((1 << word_size) ^ ciphertexts[:, 0]) - ciphertexts[:, 1]) & mask
    ciphertexts[:, 0] = common.rotate_left(alpha, ciphertexts[:, 0], word_size)


def revert_keys(
        keys: np.ndarray,
        round_number: int,
        word_size: int) -> None:
    """
    """
    number_of_kwords = keys.shape[1]
    temp = keys[:, 0].copy()
    for i in range(1, number_of_kwords - 1):
        keys[:, i - 1] = keys[:, i]
    keys[:, number_of_kwords - 2] = temp
    decrypt_function(keys[:, (number_of_kwords-2):number_of_kwords], round_number, word_size)


def decrypt(
        ciphertexts: np.ndarray,
        keys: np.ndarray,
        current_round: int,
        number_of_rounds: int,
        word_size: int) -> None:
    """
    """
    for round_number in reversed(range(current_round-number_of_rounds, current_round)):
        revert_keys(keys, round_number, word_size)
        decrypt_function(ciphertexts, keys[:, -1], word_size)