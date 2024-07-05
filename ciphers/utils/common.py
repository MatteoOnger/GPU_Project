"""
Common utilities for ciphers.
"""


# ---------------------- FUNCTIONS -------------------------
def get_mask(word_size):
    """
    Get the mask for the given word size.
    """
    return int("1" * word_size, base=2)


def rotate_left(amount, state, word_size):
    """
    Rotate the state left by the given amount.
    """
    mask = get_mask(word_size)
    rotated_state = (state << amount) ^ (state >> (word_size - amount))
    return rotated_state & mask


def rotate_right(amount, state, word_size):
    """
    Rotate the state right by the given amount.
    """
    mask = get_mask(word_size)
    rotated_state = (state << (word_size - amount)) ^ (state >> amount)
    return rotated_state & mask