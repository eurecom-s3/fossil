#!/usr/bin/env python

import itertools
import logging
from collections import defaultdict
from typing import Dict, Tuple

import compress_pickle
import numpy as np
from more_itertools import pairwise

import script_utils
from bdhash import BDHStack, DTYPE as BDHASH_DTYPE, fwd_hash
from chains import ChainGraph, POINTER_DTYPE, POINTER_SIZE, UNSIGNED_POINTER_DTYPE

OFFSET_DTYPE = np.int32
CHAIN_SIZE_DTYPE = np.uint64

hashes_dtype = np.dtype([('hash', BDHASH_DTYPE), ('direction', np.bool_), ('head', POINTER_DTYPE),
                         ('tail', POINTER_DTYPE), ('offset', OFFSET_DTYPE), ('size', CHAIN_SIZE_DTYPE)])


def arg_uniq(a):
    """The indices of each first unique element of `a`, assuming `a` is sorted."""
    if a.size == 0:
        return np.array([])
    mask = np.empty(a.shape, dtype=np.bool_)
    mask[0] = True
    mask[1:] = a[1:] != a[:-1]
    return np.flatnonzero(mask)


# noinspection PyTupleAssignmentBalance
def bd_hashes(g: ChainGraph, min_size) -> Tuple[np.ndarray, np.ndarray]:
    """Compute bidirectional hashes."""
    component2vertices = defaultdict(list)
    for i, c in enumerate(g.vp.component.a):
        component2vertices[c].append(i)

    offset = g.offset
    line_res, cycle_res = [], []

    for cycle, rtrees in g.component_breakdowns(min_size):
        diffs_min_size = min_size - 1  # np.diff(a).size == a.size - 1
        if cycle is not None:
            h0, h1 = fwd_hash(np.diff(cycle)), fwd_hash(np.diff(np.roll(cycle, -1)[::-1]))
            assert h0 != h1  # no palindromic sequences or hash conflicts
            h, direction, head, tail = (h0, 0, cycle[0], cycle[-1]) if h0 < h1 else (h1, 1, cycle[1], cycle[0])
            cycle_res.append((h, direction, head, tail, offset, cycle.size))
        for sink, parent_mapping in rtrees:
            diffs = BDHStack()
            stack = [(0, sink, parent) for parent in parent_mapping[sink]]
            while stack:
                depth, child, parent = stack.pop()
                while len(diffs) != depth:
                    assert len(diffs) > depth
                    diffs.pop()
                diffs.append(child - parent)
                depth += 1
                assert depth == len(diffs)
                if depth >= diffs_min_size:
                    h0, h1 = diffs.hash()
                    assert h0 != h1, list(diffs)  # fails for palindromic sequences or hash conflicts
                    # we should have no palindromic sequences
                    h, direction = (h0, 0) if h0 < h1 else (h1, 1)
                    line_res.append((h, direction, parent, sink, offset, depth + 1))
                stack.extend((depth, parent, grandpa) for grandpa in parent_mapping.get(parent, []))

    def process_result(res):
        res = np.array(res, hashes_dtype)
        res.sort(order=('size', 'hash', 'direction'))  # this will make further sorting quicker after
        return res

    return process_result(line_res), process_result(cycle_res)


def compute_chain(pointers, head, offset, size):
    """Compute a chain using the pointers dictionary."""

    res = [head]
    while len(res) < size:
        head = pointers[head] + offset
        res.append(head)
    return np.array(res, dtype=UNSIGNED_POINTER_DTYPE).astype(POINTER_DTYPE)


def compute_matches(data: np.ndarray, pointers: Dict[POINTER_DTYPE, POINTER_DTYPE], label: str):
    """Find matches from the hashes computed by `bd_hashes`."""

    if not len(data):
        return [], {}

    # this sorting allows grouping by hash then direction; we'll start from the bottom to prioritize longer lists
    # mergesort specifies timsort, which is faster for almost-sorted data
    data.sort(order=('size', 'hash', 'direction'), kind='mergesort')

    # Take only duplicate values. See how np.unique is implemented to get how this works.
    non_unique_mask = np.concatenate([~np.diff(data['hash']).astype(bool), [False]])
    non_unique_mask |= np.roll(non_unique_mask, 1)
    data = data[non_unique_mask]

    logging.info(f"{label}: {data.size:,} non-unique hashes")
    assigned = {}
    matches = []

    # we start from the bottom to give priority to longest chains
    for a, b in list(pairwise(itertools.chain(arg_uniq(data['hash']), [None])))[::-1]:

        group = data[a:b]  # this group contains all elements having the same (size, hash) pair
        assert len(set(group['hash'])) == 1
        assert len(set(group['size'])) == 1

        m = np.searchsorted(group['direction'], 1)  # index discriminating between the two directions
        if not 0 < m < group.size:  # hashes in just a single direction: no matches possible
            continue

        def params_boundary(rows):
            """Params for compute_chain and interval within which the reference object relating to this chain must be.

            Results are sorted by left boundary; the reference object is the head if direction == 0, 1 otherwise.
            """

            res = []
            for _, direction, head, tail, offset, size in rows:
                if head in assigned or tail in assigned:  # skip rows containing already assigned heads or tails
                    continue
                ptr = tail if direction else head
                pointed = ptr - offset  # by subtracting offset we return to what was pointed by the previous element
                bounds = ((pointed, ptr + POINTER_SIZE) if offset > 0
                          else (ptr, max(ptr + POINTER_SIZE + 1, pointed + 1)))
                res.append(((head, offset, size), bounds))
            res.sort(key=lambda pair: pair[1][1])  # sort by right bound
            return res

        fwd = params_boundary(group[:m])
        if len(fwd) == 0:
            continue
        # we use a dictionary for efficient deletion and because it preserves insertion order (by right boundary)
        bwd = dict(params_boundary(group[m:]))
        if len(bwd) == 0:
            continue

        chain = compute_chain(pointers, *fwd[0][0])
        diff = np.diff(chain)
        min_diff = np.min(np.diff(np.sort(chain)))
        assert min_diff > 0

        for (fwd_head, fwd_offset, fwd_size), (fwd_l, fwd_r) in fwd:
            # the object must be at least in the [min(bwd_l, fwd_l), max(bwd_r, fwd_r)) interval
            # this interval cannot be larger than min_diff
            # these thresholds are respectively minimum and maximum values for bwd_l and bwd_r
            min_threshold, max_threshold = fwd_r - min_diff, fwd_l + min_diff
            candidates, to_delete = [], []
            for bwd_params, (bwd_l, bwd_r) in bwd.items():  # bwd_[l,r] are left and right bounds respectively
                if bwd_l < min_threshold:
                    # since min_threshold depends on fwd_r by which fwd is sorted, bwd_params won't match from now on
                    to_delete.append(bwd_params)  # we can't delete from bwd right now, since we're iterating on it
                    continue
                if bwd_r > max_threshold:  # because of sorting, we won't find any more matches with the forward chain
                    break
                candidates.append(bwd_params)
            for bwd_params in to_delete:
                del bwd[bwd_params]
            if not candidates:
                continue
            fwd_chain = compute_chain(pointers, fwd_head, fwd_offset, fwd_size)
            assert np.array_equal(np.diff(fwd_chain), diff)  # check for hash collision
            if any(p in assigned for p in fwd_chain):
                continue

            # try to match candidates -- closest ones first
            fwd_head = fwd_chain[0]
            for bwd_params in sorted(candidates, key=lambda params: abs(fwd_head - params[0])):
                bwd_head, bwd_offset, bwd_size = bwd_params
                assert bwd_size == fwd_size
                bwd_chain = compute_chain(pointers, bwd_head, bwd_offset, bwd_size)
                assert np.array_equal(np.diff(bwd_chain[::-1]), diff)  # check for hash collision
                if any(p in assigned for p in bwd_chain):  # some pointer in this chain have already been assigned
                    del bwd[bwd_params]
                    continue
                assert len(set(fwd_chain) & set(bwd_chain)) == 0  # no cases of pointers in both directions
                assert fwd_chain[0] - bwd_chain[-1] <= min_diff
                assert (np.diff(fwd_chain - bwd_chain[::-1]) == 0).all()
                # all controls are ok! We have a match
                match_no = len(matches)
                matches.append((fwd_chain, fwd_offset, bwd_chain, bwd_offset))
                for chain in [bwd_chain, fwd_chain]:
                    for p in chain:
                        assigned[p] = match_no
                del bwd[bwd_params]
                break
    return matches, assigned


def search(graphs, min_size, pointer_set):
    pointers = dict(zip(pointer_set.src, pointer_set.dst))
    linear, cycles = [np.concatenate(arrays) for arrays in zip(*graphs.map(bd_hashes, min_size).compute())]
    logging.info(f"hashes: {linear.size:,} (linear), {cycles.size:,} (cycles)")
    return compute_matches(linear, pointers, "linear"), compute_matches(cycles, pointers, "cycles")


def main():
    parser = script_utils.setup_arg_parser()
    parser.add_argument('--min-size', type=int, default=3, help="minimum length of chains")
    args = parser.parse_args()
    script_utils.setup_logging(args)
    pointer_set = script_utils.compute_pointer_set(args)
    graphs = script_utils.compute_chain_graphs(args, pointer_set)
    res = search(graphs, args.min_size, pointer_set)
    for name, (match_list, ptr2match) in zip(["linear", "cycles"], res):
        n_matches = len(match_list)
        try:
            logging.info(f"{name}: {n_matches:,} lists (avg length {len(ptr2match) / n_matches:,.2f})")
        except ZeroDivisionError:
            logging.info("Something was wrong, 0 matches... :(")
    compress_pickle.dump(res, args.output)


if __name__ == '__main__':
    main()
