"""
Common utilities for ciphers
"""

# ---------------------- FUNCTIONS -------------------------
def encrypt_1round_feistel(feistel, texts, keys, word_size):
    feistel(texts, keys, word_size)
    temp = texts[:, 0].copy()
    texts[:, 0] = texts[:, 1]
    texts[:, 1] = temp


def decrypt_1round_feistel(feistel, texts, keys, word_size):
    temp = texts[:, 0].copy()
    texts[:, 0] = texts[:, 1]
    texts[:, 1] = temp
    feistel(texts, keys, word_size)


def use_feistel_schema(
        texts, keys, number_of_rounds, get_keys_schedule, word_size, operation, rounds_range):
    keys_schedule = get_keys_schedule(keys, number_of_rounds, word_size)
    for round_number in rounds_range:
        operation(texts, keys_schedule[:, round_number], word_size)


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