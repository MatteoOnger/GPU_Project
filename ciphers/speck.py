"""Speck

Implementation from:
https://eprint.iacr.org/2013/404.pdf
"""

import numpy as np

from ciphers.utils import common


WORD_SIZE = 32

WORD_TYPE = np.uint32

WORDSIZE_TO_ALPHABETA = {
    16: (7, 2),
    24: (8, 3),
    32: (8, 3),
    48: (8, 3),
    64: (8, 3)}


def get_keys_schedule(
        keys: np.ndarray,
        number_of_rounds: int,
        word_size: int=WORD_SIZE) -> np.ndarray:
    """Return the whole key schedule for Speck.

    :param keys: The keys.
    :type keys: np.ndarray
    :param number_of_rounds: The number of rounds that will correspond to the number of keys.
    :type number_of_rounds: int
    :param word_size: The size of the words in bits.
    :type word_size: int
    :return: The complete schedule for the keys.
    :rtype: np.ndarray
    """
    number_of_kwords = keys.shape[1]
    keys_schedule = np.empty((keys.shape[0], number_of_rounds), keys.dtype)
    keys_schedule[:, 0] = keys[:, number_of_kwords - 1]
    keys_buffer = keys.copy()
    for round_number in range(number_of_rounds - 1):
        encrypt_1round(
            keys_buffer[:, (number_of_kwords-2):number_of_kwords], round_number, word_size)
        keys_schedule[:, round_number + 1] = keys_buffer[:, number_of_kwords - 1].copy()
        temp = keys_buffer[:, number_of_kwords - 2].copy()
        for i in reversed(range(1, number_of_kwords - 1)):
            keys_buffer[:, i] = keys_buffer[:, i - 1]
        keys_buffer[:, 0] = temp
    return keys_schedule


def encrypt_1round(
        plaintexts: np.ndarray,
        keys: np.ndarray,
        word_size: int=WORD_SIZE) -> None:
    """Encrypt one round using Speck.

    :param plaintexts: The plaintexts.
    :type plaintexts: np.ndarray
    :param keys: The keys.
    :type keys: np.ndarray
    :param word_size: The size of the words in bits.
    :type word_size: int
    """
    alpha, beta = WORDSIZE_TO_ALPHABETA[word_size]
    mask = common.get_mask(word_size)
    plaintexts[:, 0] = common.rotate_right(alpha, plaintexts[:, 0], word_size)
    plaintexts[:, 0] = (plaintexts[:, 0] + plaintexts[:, 1]) & mask
    plaintexts[:, 0] ^= keys
    plaintexts[:, 1] = common.rotate_left(beta, plaintexts[:, 1], word_size)
    plaintexts[:, 1] ^= plaintexts[:, 0]


def decrypt_1round(
        ciphertexts: np.ndarray,
        keys: np.ndarray,
        word_size: int=WORD_SIZE) -> None:
    """Decrypt one round using Speck.

    :param plaintexts: The ciphertexts.
    :type plaintexts: np.ndarray
    :param keys: The keys.
    :type keys: np.ndarray
    :param word_size: The size of the words in bits.
    :type word_size: int
    """
    alpha, beta = WORDSIZE_TO_ALPHABETA[word_size]
    mask = common.get_mask(word_size)
    ciphertexts[:, 1] ^= ciphertexts[:, 0]
    ciphertexts[:, 1] = common.rotate_right(beta, ciphertexts[:, 1], word_size)
    ciphertexts[:, 0] ^= keys
    ciphertexts[:, 0] = (((1 << word_size) ^ ciphertexts[:, 0]) - ciphertexts[:, 1]) & mask
    ciphertexts[:, 0] = common.rotate_left(alpha, ciphertexts[:, 0], word_size)


def encrypt(
        plaintexts: np.ndarray,
        keys: np.ndarray,
        number_of_rounds: int,
        word_size: int=WORD_SIZE) -> None:
    """Encrypt using Speck.

    :param plaintexts: The plaintexts.
    :type plaintexts: np.ndarray
    :param keys: The keys.
    :type keys: np.ndarray
    :param number_of_rounds: The number of rounds that has to be used.
    :type number_of_rounds: int
    :param word_size: The size of the words in bits.
    :type word_size: int
    """
    keys_schedule = get_keys_schedule(keys, number_of_rounds, word_size)
    for round_number in range(number_of_rounds):
        encrypt_1round(plaintexts, keys_schedule[:, round_number], word_size)


def decrypt(
        ciphertexts: np.ndarray,
        keys: np.ndarray,
        number_of_rounds: int,
        word_size: int=WORD_SIZE) -> None:
    """Decrypt using Speck.

    :param ciphertexts: The ciphertexts.
    :type ciphertexts: np.ndarray
    :param keys: The keys.
    :type keys: np.ndarray
    :param number_of_rounds: The number of rounds that has to be used.
    :type number_of_rounds: int
    :param word_size: The size of the words in bits.
    :type word_size: int
    """
    keys_schedule = get_keys_schedule(keys, number_of_rounds, word_size)
    for round_number in reversed(range(number_of_rounds)):
        decrypt_1round(ciphertexts, keys_schedule[:, round_number], word_size)
