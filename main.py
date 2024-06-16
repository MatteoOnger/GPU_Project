import importlib
import os

import optimizer


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
    best_differences, highest_round = optimizer.optimize(
        plain_bits,
        key_bits,
        encryption_function,
        evolution_function,
        scenario=scenario,
        log_file=f"{output_dir}/{s}" if output_dir is not None else None,
        epsilon=epsilon,
    )
    return best_differences, highest_round


if __name__ == "__main__":
    find_good_input_differences("speck3264", "single-key", "evo", None)