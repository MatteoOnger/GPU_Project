"""
Common utilities for ciphers
"""


# ---------------------- FUNCTIONS -------------------------
def encrypt_feistel(feistel, texts, keys, word_size):
    feistel(texts, keys, word_size)
    temp = texts[:, 0].copy()
    texts[:, 0] = texts[:, 1]
    texts[:, 1] = temp


def decrypt_feistel(feistel, texts, keys, word_size):
    temp = texts[:, 0].copy()
    texts[:, 0] = texts[:, 1]
    texts[:, 1] = temp
    feistel(texts, keys, word_size)


def get_mask(word_size):
    return int("1" * word_size, base=2)


def rotate_left(amount, state, word_size):
    mask = get_mask(word_size)
    rotated_state = (state << amount) ^ (state >> (word_size - amount))
    return rotated_state & mask


def rotate_right(amount, state, word_size):
    mask = get_mask(word_size)
    rotated_state = (state << (word_size - amount)) ^ (state >> amount)
    return rotated_state & mask