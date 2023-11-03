cimport cython
cimport numpy as np

import numpy as np

# data types
HASH_DTYPE = np.uint64
ctypedef np.int64_t SIGNED_t
ctypedef np.uint64_t HASH_t

# constants
DEF C = 6364136223846793005  # the magic number Knuth uses
DEF INV_C = 13877824140714322085  # its inverse, found using the extended Euclidean algorithm
assert (<HASH_t> C * <HASH_t> INV_C) == 1

# cache for powers of C, will be expanded if needed
cdef HASH_t [:] powers = C ** np.arange(1024, dtype=HASH_DTYPE)


cdef class BDHash:
    cdef HASH_t s0, s1
    cdef Py_ssize_t size

    def __init__(self, iterable=()):
        self.clear()
        self.update(iterable)

    cpdef clear(self):
        self.s0 = self.s1 = self.size = 0

    cpdef append(self, item):
        cdef HASH_t v = <HASH_t> (<SIGNED_t> item)
        self.s0 = (self.s0 * <HASH_t> C) + v
        self.s1 = (self.s1 * <HASH_t> INV_C) - v
        self.size += 1

    cpdef update(self, iterable):
        for v in iterable:
            self.append(v)

    cpdef pop(self, item):
        cdef HASH_t v = <HASH_t> (<SIGNED_t> item)
        self.s0 = (self.s0 - v) * <HASH_t> INV_C
        self.s1 = (self.s1 + v) * <HASH_t> C
        self.size -= 1

    @cython.boundscheck(False)
    @cython.wraparound(False)
    cpdef hash(self):
        global powers
        while self.size > powers.size:
            powers = np.append(powers, C ** np.arange(len(powers), 2 * len(powers), dtype=np.uint64))
        return self.s0, <HASH_t> powers[self.size - 1] * self.s1


cdef class BDHStack:
    _l: list
    _h: BDHash

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
        return f"{self.__class__.__name__}({list(self)})"

    cpdef append(self, v):
        self._l.append(v)
        self._h.append(v)

    cpdef pop(self):
        v = self._l.pop()
        self._h.pop(v)
        return v

    cpdef update(self, iterable):
        for item in iterable:
            self.append(item)

    cpdef hash(self):
        return self._h.hash()
