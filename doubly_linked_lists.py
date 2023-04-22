#!/usr/bin/env python

# standard library
import logging
import os
import random
import sys
from tempfile import TemporaryDirectory

# external dependencies
import dask.bag as db
from keyvi.compiler import IntDictionaryCompiler
from keyvi.dictionary import Dictionary
from multiprocessing.managers import SharedMemoryManager
import numpy as np
from xxhash import xxh3_64 as hasher_t

# imports from this project
from chains import ChainShape

# constants
from script_utils import default_npartitions

DEFAULT_MAX_HASHES_PER_ITEM = 16384

# internal precomputed stuff
_LINE, _CYCLE = ChainShape.LINE.value, ChainShape.CYCLE.value
_chains_dtype = np.dtype([('shape', np.int64), ('chain', object), ('cutoff', np.int64), ('offset', np.int64)])
_rev_hash_dtype = np.dtype([('hash', np.uint64), ('head', np.int64), ('offset', np.int64), ('size', np.int64)])
_match_dtype = np.dtype([('offset1', np.int64), ('head1', np.int64), ('offset2', np.int64), ('size', np.int64)])


def _create_shared_memory_array(a, smm):
    shape, dtype = a.shape, a.dtype
    shm = smm.SharedMemory(size=a.nbytes)
    b = np.ndarray(shape, dtype, shm.buf)
    b[:] = a[:]
    return shm, shape, dtype


def _get_shared_memory_array(ref):
    shm, shape, dtype = ref
    return np.ndarray(shape, dtype, shm.buf)


def _process_chains(g, min_size):
    slicer = -min_size + 1  # with min_size=3, this is -2
    offset = g.offset
    seen_ptrs = set()
    for shape, chain in sorted(g.chains(min_size), key=lambda t: len(t[1]), reverse=True):
        if shape == ChainShape.CYCLE:
            yield shape.value, chain, 1, offset
        else:
            assert shape == ChainShape.LINE
            default_cut = chain.size + slicer  # note that slicer is negative
            cut = next((i for i, elem in enumerate(chain[:default_cut]) if elem in seen_ptrs),
                       default_cut)  # default value
            if cut == 0:
                continue
            yield shape.value, chain, cut, offset
            seen_ptrs.update(chain[:cut])


def _split_long_chains(t, max_hashes_per_item):
    shape, chain, cutoff, offset = t
    while cutoff > max_hashes_per_item:
        yield shape, chain, max_hashes_per_item, offset
        chain = chain[max_hashes_per_item:]
        cutoff -= max_hashes_per_item
    yield shape, chain, cutoff, offset


def _hash_reversed_diff(chains):
    res = []
    hasher = hasher_t()
    for shape, chain, n, offset in chains:
        inv_chain = chain[::-1]
        inv_diff = np.diff(inv_chain)
        if shape == _CYCLE:
            hasher.reset()
            hasher.update(inv_diff)
            res.append((hasher.intdigest(), chain[0], offset, chain.size))
            continue
        else:
            assert shape == _LINE
            hasher.reset()
            skipped = inv_diff.size - n
            hasher.update(inv_diff[:skipped])
            for d, elem, size in zip(inv_diff[skipped:], inv_chain[skipped + 1:], range(skipped + 2, chain.size + 1)):
                hasher.update(d)
                res.append((hasher.intdigest(), elem, offset, size))
    return [np.array(res, _rev_hash_dtype)]


def _hash_matches(chains, rev_hashes_ref, h2i_filename):
    rev_hashes = _get_shared_memory_array(rev_hashes_ref)
    h2i = Dictionary(h2i_filename)
    res = set()
    hasher = hasher_t()

    def add_matches(diff_array, head, chain_size):
        hasher.reset()
        hasher.update(diff_array)
        match = h2i.get(hasher.digest())
        if match is None:
            return False
        idx = match.GetValue()
        tail = chain[-1]
        pointed_tail = tail - offset
        min_diff = np.abs(diff_array).min()
        int_h_first = rev_hashes[idx][0]
        found = False
        for int_h_other, head_other, offset_other, size_other in rev_hashes[idx:]:
            if int_h_other != int_h_first:
                break  # we got to another hash, stop iterating
            if size_other != chain_size:
                logging.warning(f"Hash collision found at hash {int_h_other}!")
                continue  # a hash collision--should be extremely unlikely
                # we don't find all collisions this way; false positives are extremely unlikely but still possible
            if max(abs(pointed_tail - head_other + offset_other), abs(offset_other - offset)) > min_diff:
                continue  # the two chains are too far away to be a doubly linked list
            found = True
            if (offset, head) < (offset_other, head_other):
                res.add((offset, head, offset_other, head_other, chain_size))
            else:
                res.add((offset_other, head_other, offset, head, chain_size))
        return found

    for shape, chain, n, offset in chains:
        if shape == _CYCLE:
            chain = np.roll(chain, -1)
            add_matches(np.diff(chain), chain[0], chain.size)
        else:
            assert shape == _LINE
            diff = np.diff(chain)
            size = chain.size
            for i in range(n):
                if add_matches(diff[i:], chain[i], size - i):
                    break
    return res


def search(graphs: db.core.Bag, min_size: int = 3, npartitions: int = default_npartitions(),
           max_hashes_per_item: int = DEFAULT_MAX_HASHES_PER_ITEM, shuffle: bool = True, tmp_dir: str = None):
    logging.info("Computing chains")
    chains = graphs.map(_process_chains, min_size).flatten()\
        .map(_split_long_chains, max_hashes_per_item).flatten()
    if shuffle:
        chains = chains.compute()
        logging.info("Shuffling to distribute load")  # TODO find a way to do it in a non-single-threaded way
        random.shuffle(chains)
        chains = db.from_sequence(chains, npartitions=npartitions).persist()
    else:
        chains = chains.repartition(npartitions).persist()
    logging.info("Computing backward hashing_data")
    rev_hashes = chains.map_partitions(_hash_reversed_diff).compute()
    rev_hashes = np.concatenate(rev_hashes)
    rev_hashes = rev_hashes[np.argsort(rev_hashes['hash'])]
    logging.info(f"{rev_hashes.size:,} hashing_data computed")

    logging.info("Computing hash-to-index mapping")
    compiler = IntDictionaryCompiler()
    hashes, index = np.unique(rev_hashes['hash'], return_index=True)
    if sys.byteorder == 'little':
        hashes = hashes.newbyteorder()
    for h, i in zip(hashes, index):
        compiler.Add(h.tobytes(), int(i))
    compiler.Compile()
    with TemporaryDirectory(dir=tmp_dir) as d:
        h2i_filename = os.path.join(d, 'h2i.kv')
        compiler.WriteToFile(h2i_filename)
        logging.info("Computing matches")
        with SharedMemoryManager() as smm:
            smm: SharedMemoryManager  # shuts up a PyCharm type checker warning
            rev_hashes = _create_shared_memory_array(rev_hashes, smm)
            return set(chains.map_partitions(_hash_matches, rev_hashes, h2i_filename).compute())


def main():
    import argparse

    import compress_pickle
    from dask.diagnostics import ProgressBar

    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='+')
    parser.add_argument('result')
    parser.add_argument('--min-size', type=int, default=3, help="minimum length of chains")
    parser.add_argument('--npartitions', type=int, default=default_npartitions())
    parser.add_argument('--max-hashing_data-per-item', type=int, default=DEFAULT_MAX_HASHES_PER_ITEM)
    parser.add_argument('--no-shuffle', action='store_true')
    parser.add_argument('--tmp-dir', help="directory in which to store temporary data")
    parser.add_argument('--silent', action='store_true')
    args = parser.parse_args()

    # noinspection PyArgumentList
    logging.basicConfig(format="{levelname} {asctime} {message}", style='{',
                        level=logging.WARNING if args.silent else logging.INFO)
    if not args.silent:
        ProgressBar().register()
    graphs = db.from_sequence(args.filenames, npartitions=min(len(args.filenames), args.npartitions))\
        .map(compress_pickle.load)
    matches = search(graphs, args.min_size, args.npartitions, args.max_hashes_per_item, not args.no_shuffle,
                     args.tmp_dir)
    logging.info(f"{len(matches):,} matches found")
    compress_pickle.dump(matches, args.result)


if __name__ == '__main__':
    main()
