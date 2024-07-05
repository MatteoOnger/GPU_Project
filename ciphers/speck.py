"""
Speck Cipher

Implementation from: https://eprint.iacr.org/2013/404.pdf.
"""
# --------------------------------------------------------------------------- #
# NOTE:
#  The following functions can be invoked by passing both numpy arrays
#  and cupy arrays as parameters. In the first case the computation is 
#  performed by the CPU, in the second case by the GPU.
# --------------------------------------------------------------------------- #

import cupy as cp
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
Rotation amounts for each cipher configuration.
"""


# ---------------------- FUNCTIONS -------------------------
def encrypt_function(plaintexts: cp.ndarray|np.ndarray, keys: cp.ndarray|np.ndarray, word_size: int) -> None:
    """
    Encrypt one round using Speck.
    Encryption is done in-place.

    Parameters
    ----------
    ``plaintexts``: numpy.ndarray or cupy.ndarray of shape ``(N, plain_size)``
        ``N`` plaintexts, each consisting of ``plain_size`` words.
    ``keys``: numpy.ndarray or cupy.ndarray of shape ``(N, key_size)``
        ``N`` keys, each consisting of ``key_size`` words.
    ``word_size``: int
        The size of the words in bits.
    """
    alpha, beta = WORDSIZE_TO_ALPHABETA[word_size]
    mask = common.get_mask(word_size)
    plaintexts[:, 0] = common.rotate_right(alpha, plaintexts[:, 0], word_size)
    plaintexts[:, 0] = (plaintexts[:, 0] + plaintexts[:, 1]) & mask
    plaintexts[:, 0] ^= keys
    plaintexts[:, 1] = common.rotate_left(beta, plaintexts[:, 1], word_size)
    plaintexts[:, 1] ^= plaintexts[:, 0]
    return


def update_keys(keys: cp.ndarray|np.ndarray, round_number: int, word_size: int) -> None:
    """
    Update the keys in-place.

    Parameters
    ----------
    ``keys``: numpy.ndarray or cupy.ndarray of shape ``(N, key_size)``
        ``N`` keys, each consisting of ``key_size`` words.
    ``round_number``: int
        The current round number.
    ``word_size``: int
        The size of the words in bits.
    """
    number_of_kwords = keys.shape[1]
    encrypt_function(keys[:, (number_of_kwords-2):number_of_kwords], round_number, word_size)
    temp = keys[:, number_of_kwords - 2].copy()
    for i in reversed(range(1, number_of_kwords - 1)):
        keys[:, i] = keys[:, i - 1]
    keys[:, 0] = temp
    return


def encrypt(plaintexts: cp.ndarray|np.ndarray,
        keys: cp.ndarray|np.ndarray,
        current_round: int,
        number_of_rounds: int, 
        word_size: int) -> None:
    """
    Encrypt in-place using Speck.

    Parameters
    ----------
    ``plaintexts``: numpy.ndarray or cupy.ndarray of shape ``(N, plain_size)``
        ``N`` plaintexts, each consisting of ``plain_size`` words.
    ``keys``: numpy.ndarray or cupy.ndarray of shape ``(N, key_size)``
        ``N`` keys, each consisting of ``key_size`` words.
    ``current_round``: int
        The current round number.
    ``number_of_rounds``: int
        The number of rounds to encrypt for.
    ``word_size``: int
        The size of the words in bits.
    """
    for round_number in range(current_round, current_round+number_of_rounds):
        encrypt_function(plaintexts, keys[:, -1], word_size)
        update_keys(keys, round_number, word_size)
    return


def decrypt_function(ciphertexts: np.ndarray, keys: np.ndarray, word_size: int) -> None:
    """
    Decrypt one round using Speck in-place.

    Parameters
    ----------
    ``ciphertexts``: numpy.ndarray or cupy.ndarray of shape ``(N, text_size)``
        ``N`` ciphertexts, each consisting of ``text_size`` words.
    ``keys``: numpy.ndarray or cupy.ndarray of shape ``(N, key_size)``
        ``N`` keys, each consisting of ``key_size`` words.
    ``word_size``: int
        The size of the words in bits.
    """
    alpha, beta = WORDSIZE_TO_ALPHABETA[word_size]
    mask = common.get_mask(word_size)
    ciphertexts[:, 1] ^= ciphertexts[:, 0]
    ciphertexts[:, 1] = common.rotate_right(beta, ciphertexts[:, 1], word_size)
    ciphertexts[:, 0] ^= keys
    ciphertexts[:, 0] = (((1 << word_size) ^ ciphertexts[:, 0]) - ciphertexts[:, 1]) & mask
    ciphertexts[:, 0] = common.rotate_left(alpha, ciphertexts[:, 0], word_size)
    return


def revert_keys(keys: cp.ndarray|np.ndarray, round_number: int, word_size: int) -> None:
    """
    Revert the keys in-place.

    Parameters
    ----------
    ``keys``: numpy.ndarray or cupy.ndarray of shape ``(N, key_size)``
        ``N`` keys, each consisting of ``key_size`` words.
    ``round_number``: int
        The current round number.
    ``word_size``: int
        The size of the words in bits.
    """
    number_of_kwords = keys.shape[1]
    temp = keys[:, 0].copy()
    for i in range(1, number_of_kwords - 1):
        keys[:, i - 1] = keys[:, i]
    keys[:, number_of_kwords - 2] = temp
    decrypt_function(keys[:, (number_of_kwords-2):number_of_kwords], round_number, word_size)
    return


def decrypt(ciphertexts: cp.ndarray|np.ndarray,
        keys: cp.ndarray|np.ndarray,
        current_round: int,
        number_of_rounds: int,
        word_size: int) -> None:
    """
    Dencrypt in-place using Speck.

    Parameters
    ----------
    ``ciphertexts``: numpy.ndarray or cupy.ndarray of shape ``(N, text_size)``
        ``N`` ciphertexts, each consisting of ``text_size`` words.
    ``keys``: numpy.ndarray or cupy.ndarray of shape ``(N, key_size)``
        ``N`` keys, each consisting of ``key_size`` words.
    ``current_round``: int
        The current round number.
    ``number_of_rounds``: int
        The number of rounds to encrypt for.
    ``word_size``: int
        The size of the words in bits.
    """
    for round_number in reversed(range(current_round-number_of_rounds, current_round)):
        revert_keys(keys, round_number, word_size)
        decrypt_function(ciphertexts, keys[:, -1], word_size)
    return