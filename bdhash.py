import logging
import numpy as np
import warnings
from numpy.typing import NDArray
from typing import Iterable, List

#########################
# Data initialization   #
#########################
warnings.filterwarnings('ignore', 'overflow encountered in', RuntimeWarning, __name__)
C = np.uint64(6364136223846793005)  # the magic number Knuth uses
INV_C = np.uint64(pow(int(C), -1, 2 ** 64))
assert C * INV_C == 1
powers = C ** np.arange(1024, dtype=np.uint64)  # will be expanded if needed


def _expand_powers():
    global powers
    powers = np.append(powers, C ** np.arange(len(powers), 2 * len(powers), dtype=np.uint64))

def compute_forward_hash(sequence: NDArray) -> np.uint64:
    sequence_length = len(sequence)
    while sequence_length > powers.size:
        _expand_powers()
    hash_value = np.uint64(0)
    for value, power in zip(sequence, reversed(powers[:sequence_length])):
        hash_value += power * np.uint64(value)
    return hash_value


class PyBDHash(object):
    h0: np.uint64
    _s1: np.uint64
    size: int

    def __init__(self, iterable=()):
        self.clear()
        self.update(iterable)

    def clear(self):
        self.h0 = np.uint64(0)
        self._s1 = np.uint64(0)
        self.size = 0

    def append(self, v):
        v = np.uint64(v)
        self.h0  = (self.h0 * C) + v
        self._s1 = (self._s1 * INV_C) - v
        self.size += 1

    def update(self, iterable):
        for v in iterable:
            self.append(v)

    def pop(self, v):
        v = np.uint64(v)
        self.h0 = (self.h0 - v) * INV_C
        self._s1 = (self._s1 + v) * C
        self.size -= 1

    def hash(self):
        global powers
        while self.size > powers.size:
            _expand_powers()
        return self.h0, powers[self.size - 1] * self._s1

class PyBDHStack:
    _l: List[np.ndarray]
    _h: PyBDHash

    def __init__(self, iterable=()):
        self._l = lst = list(iterable)
        self._h = BDHash(lst)

    def __getitem__(self, item):
        return self._l[item]

    def __len__(self):
        return self._h.size

    def __iter__(self):
        yield from self._l

    def __str__(self):
        return f'{self.__class__.__name__}({list(self)})'

    def append(self, v):
        self._l.append(v)
        self._h.append(v)

    def pop(self):
        v = self._l.pop()
        self._h.pop(v)
        return v

    def update(self, iterable: Iterable[np.uint64]):
        for item in iterable:
            self.append(item)

    def hash(self):
        return self._h.hash()

try:
    from cython_bdhash import BDHash, BDHStack # type:ignore
except ImportError:
    logging.warn('Cython-compiled version of bdhash not available, compile with `python setup.py build_ext --inplace`')
    BDHash, BDHStack = PyBDHash, PyBDHStack
