import importlib
import numpy as np
import os
import pandas as pd

from os import urandom


# Number of samples used to compute the score of each difference considered
# Original paper: 10**4
NUMBER_OF_SAMPLES_FOR_BIAS_SCORE = 10**3


def bit_array_to_integers(arr :list[list[int]]) -> list[int]:
    """
    Trasform each array of bits into an integer.

    Parameters
    ----------
    ``arr``: list of bit of shape(m, n)
        List of bit arrays.

    Return
    ----------
    Return a list of integers of shape(m).
    """
    packed = np.packbits(arr, axis=1)
    return [int.from_bytes(x.tobytes(), "big") for x in packed]

def dataframe_from_sorted_differences(differences, scores, scenario, plain_bits, key_bits=0):
    idx = np.arange(len(differences))
    good = idx[np.argsort(scores)]
    sorted_diffs = differences[good]
    sorted_scores = scores[good].round(4)
    diffs_to_print = bit_array_to_integers(sorted_diffs)
    data = []
    for idx, d in enumerate(diffs_to_print):
        if scenario == "related-key":
            data.append(
                [
                    ({hex(d >> key_bits)}, {hex(d & (2**key_bits - 1))}),
                    {sorted_scores[idx]},
                ]
            )
        else:
            data.append([{hex(d)}, {sorted_scores[idx]}])
    df = pd.DataFrame(data, columns=["Difference", "Weighted score"])
    return df

def pretty_print_best_epsilon_close_differences(differences, scores, epsilon, scenario, plain_bits, key_bits=0):
    idx = np.arange(len(differences))
    order = idx[np.argsort(scores)]
    sorted_diffs = differences[order]
    sorted_scores = scores[order].round(4)
    best_score = sorted_scores[-1]
    threshold = best_score * (1 - epsilon)
    keep = np.where(sorted_scores > threshold)
    diffs_to_print = bit_array_to_integers(sorted_diffs[keep])
    scores_to_print = sorted_scores[keep]
    resStr = ""
    for idx, d in enumerate(diffs_to_print):
        if scenario == "related-key":
            resStr = f"{resStr}[{hex(d)} ({hex(d>>key_bits)}, {hex(d&(2**key_bits-1))}), {scores_to_print[idx]}]\n"
        else:
            resStr = f"{resStr}[{hex(d)}, {scores_to_print[idx]}]\n"
    return resStr, sorted_diffs[keep], diffs_to_print

def pretty_print_best_n_differences(differences, scores, n, scenario, plain_bits, key_bits=0):
    idx = np.arange(len(differences))
    good = idx[np.argsort(scores)]
    sorted_diffs = differences[good]
    sorted_scores = scores[good].round(4)[-n:]
    diffs_to_print = bit_array_to_integers(sorted_diffs)[-n:]
    resStr = ""
    for idx, d in enumerate(diffs_to_print):
        if scenario == "related-key":
            resStr = f"{resStr}[{hex(d)} ({hex(d>>key_bits)}, {hex(d&(2**key_bits-1))}), {sorted_scores[idx]}]\n"
        else:
            resStr = f"{resStr}[{hex(d)}, {sorted_scores[idx]}]\n"
    return resStr, sorted_diffs[-n:], diffs_to_print


def evaluate_multiple_differences(
        candidate_differences :np.ndarray,
        plaintexts :np.ndarray,
        keys :np.ndarray,
        ciphertexts :np.ndarray,
        number_of_rounds :int,
        plain_bits :int,
        key_bits :int,
        encrypt :callable,
        scenario :str="single-key",
    ) -> tuple[float]:
    """
    Computes the bias scores of several candidate differences, based on the initial plaintexts,
    keys and the corresponding ciphertexts, for ``number_of_rounds`` rounds of a cipher with
    ``plain_bits`` plaintext bits and ``key_bits`` key bits.

    Parameters
    ----------
    ``candidate_differences``: np.ndarray
        Array of candidate differences.
    ``plaintexts``: np.ndarray
        Array of plaintexts used to compute the bias scores.
    ``keys``: np.ndarray
        Array of keys used to encrypt the plaintexts.
    ``ciphertexts``: np.ndarray
        Array of ciphertexts used to compute the bias scores.
    ``number_of_rounds``: int
        Number of rounds performed during encryption.
    ``plain_bits``: int
        Block size.
    ``key_bits``: int
        key size.
    ``encrypt``: callable
        Function used to encrypt the texts.
    ``scenario``: string
        If it is set to ``single-key``, the same key is used to encrypt both the inputs of a ciphertext pair;
        while if it is set to ``related-key``, two different keys are used and their difference is considered too.

    Return
    ----------
    Return a score for each candidate differences given in input.
    """
    dp = candidate_differences[:, :plain_bits]
    plaintexts_xor_differences = (
        np.broadcast_to(
            dp[:, None, :], (len(candidate_differences), len(plaintexts), plain_bits)
        )
        ^ plaintexts
    ).reshape(-1, plain_bits)
    if scenario == "related-key":
        dk = candidate_differences[:, plain_bits:]
    else:
        dk = np.zeros((len(candidate_differences), key_bits), dtype=np.uint8)
    keys_xor_differences = (
        np.broadcast_to(
            dk[:, None, :], (len(candidate_differences), len(plaintexts), key_bits)
        )
        ^ keys
    ).reshape(-1, key_bits)
    ciphertexts_from_xordiff_inputs = encrypt(plaintexts_xor_differences, keys_xor_differences, number_of_rounds)
    ciphertexts_differences = ciphertexts_from_xordiff_inputs.reshape(len(candidate_differences), len(plaintexts), -1) ^ ciphertexts
    scores = np.average(np.abs(0.5 - np.average(ciphertexts_differences, axis=1)), axis=1)
    # Setting the score to zero if the difference is 0x0
    zero_diffs = np.where(np.sum(candidate_differences, axis=1) == 0)
    scores[zero_diffs] = 0
    return scores

def optimize(
        plain_bits :int,
        key_bits :int,
        encryption_function :callable,
        evolution_function :callable,
        nb_samples :int=NUMBER_OF_SAMPLES_FOR_BIAS_SCORE,
        scenario :str="single-key",
        log_file :str|None=None,
        epsilon :float=0.1,
    ) -> tuple[list[int], int]:
    """
    Find good input differences for the differential-ML distinguisher given a specific cipher and an evolutionary algorithm to use.
    The function returns a list of differences and the highest round reached.

    Parameters
    ----------
    ``plain_bits``: int
        Plaintext block size.
    ``key_bits``: int
        Size of the key.
    ``encryption_function``: callable
        Function used to encrypt a message.
    ``evolution_function``: callable
        Evolutionary algorithm used to produce cadidate differences.
    ``nb_samples``: int
        Number of samples used to compute the score.
    ``scenario``: string in [``single-key``, ``related-key``]
        If it is set to ``single-key``, the same key is used to encrypt both the inputs of a ciphertext pair;
        while if it is set to ``related-key``, two different keys are used and their difference is considered too.
    ``log_file``: string|None
        Log file name.
    ``epsilon``: float between [0, 1]
        Highlights the differences that have score only ``epsilon`` lower than the best found.

    Return
    ----------
    Return a tuple ``(x, y)`` where ``x`` is a list of differences and ``y`` the highest round reached.
    """
    diffs = None
    all_diffs = None
    bias_score_threshold = 0.05
    current_round = 1

    if scenario == "single-key":
        bits_to_search = plain_bits
    else:
        bits_to_search = plain_bits + key_bits

    while True:
        keys0 = (np.frombuffer(urandom(nb_samples * key_bits), dtype=np.uint8) & 1).reshape(nb_samples, key_bits)
        pt0 = (np.frombuffer(urandom(nb_samples * plain_bits), dtype=np.uint8) & 1).reshape(nb_samples, plain_bits)
        C0 = encryption_function(pt0, keys0, current_round)
        diffs, scores = evolution_function(
            f=lambda x: evaluate_multiple_differences(
                x,
                pt0,
                keys0,
                C0,
                current_round,
                plain_bits,
                key_bits,
                encryption_function,
                scenario=scenario,
            ),
            num_bits=bits_to_search,
            L=32,
            gen=diffs,
            verbose=1,
        )
        if all_diffs is None:
            all_diffs = diffs
        else:
            all_diffs = np.concatenate([all_diffs, diffs])
        current_round += 1
        if scores[-1] < bias_score_threshold:
            break

    # Re-evaluate all differences for best round
    all_diffs = np.unique(all_diffs, axis=0)
    final_scores = [None for i in range(current_round)]
    cumulative_scores = np.zeros(len(all_diffs))
    weighted_scores = np.zeros(len(all_diffs))

    if log_file is not None:
        with open(log_file, "a") as f:
            f.write(f"New log start, reached round {str(current_round-1)} \n")
    
    for nr in range(1, current_round):
        keys0 = (np.frombuffer(urandom(nb_samples * key_bits), dtype=np.uint8) & 1).reshape(nb_samples, key_bits)
        pt0 = (np.frombuffer(urandom(nb_samples * plain_bits), dtype=np.uint8) & 1).reshape(nb_samples, plain_bits)
        C0 = encryption_function(pt0, keys0, nr)
        final_scores[nr] = evaluate_multiple_differences(
            all_diffs,
            pt0,
            keys0,
            C0,
            nr,
            plain_bits,
            key_bits,
            encryption_function,
            scenario=scenario,
        )
        cumulative_scores += np.array(final_scores[nr])
        weighted_scores += nr * np.array(final_scores[nr])

        result, _, _ = pretty_print_best_n_differences(all_diffs, final_scores[nr], 5, scenario, plain_bits, key_bits)
        resStr = f"Best at {nr}: \n{result}"
        if log_file is not None:
            with open(log_file, "a") as f:
                f.write(resStr)

    result, _, _ = pretty_print_best_n_differences(
        all_diffs, cumulative_scores, 5, scenario, plain_bits, key_bits
    )
    resStr = f"Best Cumulative: \n{result}"
    if log_file is not None:
        with open(log_file, "a") as f:
            f.write(resStr)

    result, _, _ = pretty_print_best_n_differences(
        all_diffs, weighted_scores, 5, scenario, plain_bits, key_bits
    )
    resStr = f"Best Weighted: \n{result}"
    if log_file is not None:
        with open(log_file, "a") as f:
            f.write(resStr)

    result, _, diffs_as_hex = pretty_print_best_epsilon_close_differences(
        all_diffs, weighted_scores, epsilon, scenario, plain_bits, key_bits
    )

    if log_file is not None:
        df = dataframe_from_sorted_differences(
            all_diffs, weighted_scores, scenario, plain_bits, key_bits
        )
        df.to_csv(f"{log_file}_best_weighted_differences.csv")
    return diffs_as_hex, current_round

def find_good_input_differences(cipher_name :str, scenario :str, evoalg_name :str, output_dir :str|None=None, epsilon :float=0.1) -> tuple[list[int], int]:
    """
    Find good input differences for the differential-ML distinguisher.
    The function returns a list of differences and the highest round reached.

    Parameters
    ----------
    ``cipher_name``: string
        The name of the considered cipher.
    ``scenario``: string in [``single-key``, ``related-key``]
        If it is set to ``single-key``, the same key is used to encrypt both the inputs of a ciphertext pair;
        while if it is set to ``related-key``, two different keys are used and their difference is considered too.
    ``evoalg_name``: string
        The name of the evolutionary algorithm used by the optimizer.
    ``output_dir``: string|None
        Log file's directory. If ``None``, resutls are not saved.
    ``epsilon``: float between [0, 1]
        Highlights the differences that have score only ``epsilon`` lower than the best found.

    Return
    ----------
    Return a tuple ``(x, y)`` where ``x`` is a list of differences and ``y`` the highest round reached.
    """
    if scenario not in ["single-key", "related-key"]:
        raise ValueError("unkown scenario")

    if (output_dir is not None) and (not os.path.exists(output_dir)):
        os.makedirs(output_dir)
    
    cipher = importlib.import_module(f"ciphers.{cipher_name}", package="ciphers")
    evoalg = importlib.import_module(f"evoalgs.{evoalg_name}", package="evoalgs")

    plain_bits = cipher.plain_bits
    key_bits = cipher.key_bits
    encryption_function = cipher.encrypt
    evolution_function = evoalg.run

    s = f"{cipher_name}_{scenario}_{evoalg_name}"
    best_differences, highest_round = optimize(
        plain_bits,
        key_bits,
        encryption_function,
        evolution_function,
        scenario=scenario,
        log_file=f"{output_dir}/{s}" if output_dir is not None else None,
        epsilon=epsilon,
    )
    return best_differences, highest_round