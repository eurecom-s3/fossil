import logging
from typing import Iterable, List, Sequence
import warnings

import numpy as np

warnings.filterwarnings('ignore', 'overflow encountered in ulong_scalars', RuntimeWarning, __name__)


def _inverse(x, m):
    # Extended Euclidean algorithm: https://stackoverflow.com/a/14093613/550097
    a, b, u = 0, m, 1
    while x > 0:
        q, r = divmod(b, x)
        x, a, b, u = b % x, u, x, a - q * u
    if b == 1:
        return a % m
    raise ValueError("must be co-prime")


DTYPE = np.uint64
C = DTYPE(6364136223846793005)  # the magic number Knuth uses
INV_C = DTYPE(_inverse(int(C), 2 ** 64))
assert C * INV_C == 1
powers = C ** np.arange(1024, dtype=DTYPE)  # will be expanded if needed


def _expand_powers():
    global powers
    powers = np.append(powers, C ** np.arange(len(powers), 2 * len(powers), dtype=DTYPE))


def fwd_hash(seq: Sequence):
    n = len(seq)
    while n > powers.size:
        _expand_powers()
    s = DTYPE(0)
    for v, p in zip(seq, reversed(powers[:n])):
        s += p * DTYPE(v)
    return s


class PyBDHash(object):
    h0: DTYPE
    _s1: DTYPE
    size: int

    def __init__(self, iterable=()):
        self.clear()
        self.update(iterable)

    def clear(self):
        self.h0 = DTYPE(0)
        self._s1 = DTYPE(0)
        self.size = 0

    def append(self, v):
        v = DTYPE(v)
        self.h0 *= C
        self.h0 += v
        self._s1 *= INV_C
        self._s1 -= v
        self.size += 1

    def update(self, iterable):
        for v in iterable:
            self.append(v)

    def pop(self, v):
        v = DTYPE(v)
        self.h0 -= v
        self.h0 *= INV_C
        self._s1 += v
        self._s1 *= C
        self.size -= 1

    def hash(self):
        global powers
        size = self.size
        while size > len(powers):
            _expand_powers()
        return self.h0, powers[size - 1] * self._s1


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

    def append(self, v):
        self._l.append(v)
        self._h.append(v)

    def pop(self):
        v = self._l.pop()
        self._h.pop(v)
        return v

    def update(self, iterable: Iterable[DTYPE]):
        for item in iterable:
            self.append(item)

    def hash(self):
        return self._h.hash()


try:
    from cython_bdhash import BDHash, BDHStack
except ImportError:
    logging.warn("Cython-compiled version of bdhash not available, compile with `python setup.py build_ext --inplace`")
    BDHash, BDHStack = PyBDHash, PyBDHStack


def main():
    import cython_bdhash

    rng = np.random.default_rng()
    array = rng.integers(-1_000_000_000, 1_000_000_000, 20_000)
    res = []
    for Stack in [PyBDHStack, cython_bdhash.BDHStack]:
        hasher1 = Stack(array)
        assert hasher1.hash()[0] == fwd_hash(array), fwd_hash(array)
        hasher2 = Stack(-array[::-1])
        assert hasher1.hash() == hasher2.hash()[::-1], (hasher1.hash(), hasher2.hash())
        hasher1.pop()
        hasher3 = BDHStack(-array[:-1][::-1])
        assert hasher1.hash() == hasher3.hash()[::-1]
        res.append((hasher1.hash(), hasher2.hash()))
    assert res[0] == res[1]


if __name__ == '__main__':
    main()
