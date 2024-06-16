import numpy as np


# Number of generations considered in the evolutionary algorithm
# in the original paper: 50
NUMBER_OF_GENERATIONS = 5


def run(
        f :callable, 
        n :int=NUMBER_OF_GENERATIONS,
        num_bits :int=32,
        L :int=32,
        gen :np.ndarray=None,
        verbose :bool=False
    ) -> tuple[np.ndarray, np.ndarray]:
    """
    Evolutionary algorithm based on the function ``f``, 
    running for ``n`` generations, using differences of ``num_bits`` bits, a population size of ``L``, an
    optional initial population ``gen``, and verbosity set to 0 for silent or 1 for verbose.

    Parameters
    ----------
    ``f``: callable
        Function used to evaluate the quality of a difference.
    ``n``: int
        Number of generations.
    ``num_bits``: int
        Length in bits of the differences.
    ``L``: int
        Size of the population.
    ``gen``: array
        Initial population. If not set, it is randomly generated.
    ``verbose``: boolean
        Verbosity.
    
    Return
    ----------
    Returns a tuple containing two parallel lists: the first contains the differences produced,
    while the second contains the scores of each difference.
    """
    mutProb = 100
    if gen is None:
        gen = np.random.randint(2, size=(L**2, num_bits), dtype=np.uint8)
    scores = f(gen)
    idx = np.arange(len(gen))
    explored = np.copy(gen)
    good = idx[np.argsort(scores)][-L:]
    gen = gen[good]
    scores = scores[good]
    cpt = len(gen)
    for generation in range(n):
        # New generation
        kids = np.array(
            [gen[i] ^ gen[j] for i in range(len(gen)) for j in range(i + 1, len(gen))],
            dtype=np.uint8,
        )
        # Mutation: selecting mutating kids
        selected = np.where(np.random.randint(0, 100, len(kids)) > (100 - mutProb))
        numMut = len(selected[0])
        # Selected kids are XORed with 1 << r (r random)
        kids[selected[0].tolist(), np.random.randint(num_bits, size=numMut)] ^= 1
        # Removing kids that have been explored before and duplicates
        kids = np.unique(kids[(kids[:, None] != explored).any(-1).all(-1)], axis=0)
        # Appending to explored
        explored = np.vstack([explored, kids])
        cpt += len(kids)
        # Computing the scores
        if len(kids) > 0:
            scores = np.append(scores, f(kids))
            gen = np.vstack([gen, kids])
            # Sorting, keeping only the L best ones
            idx = np.arange(len(gen))
            good = idx[np.argsort(scores)][-L:]
            gen = gen[good]
            scores = scores[good]
        if verbose:
            genInt = np.packbits(gen[-4:, :], axis=1)
            hexGen = [hex(int.from_bytes(x.tobytes(), "big")) for x in genInt]
            print(
                f"Generation {generation}/{n}, {cpt} nodes explored, {len(gen)} current,"
                f" best is {list(hexGen)} with {scores[-4:]}",
                flush=True,
            )
        if np.all(scores == 0.5):
            break
    return gen, scores