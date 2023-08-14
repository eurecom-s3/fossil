#!/usr/bin/env -S python3 -u

import itertools
import logging
from collections import defaultdict

import compress_pickle
import dask.array as da
import numpy as np
import sortednp as snp
from sortedcontainers import SortedList

import script_utils
from chains import distance_threshold, PointerSet, within_threshold
import ctypes

POINTER_DTYPE = np.uint64
POINTER_SIZE = 8

try:
    from itertools import pairwise
except ImportError:  # python < 3.10
    from more_itertools import pairwise


def tree_elements(ptr, ptrs, offsets, depth):
    this = np.array([ptr], dtype=POINTER_DTYPE)
    if depth == 0:
        return this
    children = [tree_elements(ptrs[ctypes.c_uint64(ptr).value + ctypes.c_int32(o).value], ptrs, offsets, depth - 1) for o in offsets]
    return snp.kway_merge(this, *children, duplicates=snp.KEEP)

def tree_elements_breadth(root, ptrs, offsets, levels):
    elements = [ctypes.c_uint64(root).value]
    offsets = [ctypes.c_int32(o).value for o in offsets]
    new_elems = []

    for level in range(levels+1):
        # print(level, len(elements))
        new_elems.clear()
        for next_elem in elements[2**level - 1:]:
            if next_elem is None:
                elements.append(None)
                elements.append(None)
                continue
            else:
                for offset in offsets:
                    if next_elem + offset in ptrs:
                        new_elems.append(ptrs[next_elem + offset])
                    else:
                        new_elems.append(None)
        
        if all([x is None for x in new_elems]):
            break
        else:
            elements.extend(new_elems)
    return elements


def tree_depth(ptr, ptrs, offsets):  # TODO buggy when there's a loop, doesn't check distance thresholds
    def depth(p):
        try:
            return min(depth(ptrs[p + o]) for o in offsets) + 1
        except KeyError:
            return 0
    return depth(ptr)


def filled_level_tree_nodes(ptr, ptrs, offsets):  # TODO buggy when there's a loop, doesn't check distance thresholds
    def nodes(p):
        this = np.array([p])
        try:
            children = [nodes(ptrs[p + o]) for o in offsets]
        except KeyError:
            return this
        else:
            return snp.kway_merge(this, *children, duplicates=snp.KEEP)
    return nodes(ptr)


def all_tree_nodes(ptr, ptrs, offsets):  # TODO buggy when there's a loop, doesn't check distance thresholds
    def nodes(p):
        to_merge = [nodes(ptrs[p + o]) for o in offsets if p + o in ptrs]
        return snp.kway_merge(np.array([p]), *to_merge, duplicates=snp.KEEP)
    return nodes(ptr)


def get_len2_chains(offsets: np.ndarray, pointer_set: PointerSet):
    assert offsets.size == 1
    offset = offsets[0]
    src, dst = pointer_set.src, pointer_set.dst
    # noinspection PyTypeChecker
    in_range: np.ndarray = abs(dst - src) >= distance_threshold(offset)
    src, dst = src[in_range], dst[in_range]
    dst_sorting = np.argsort(dst)
    intersection, (pointed_ind, _) = snp.intersect(src, dst[dst_sorting] + offset, indices=True)
    return np.stack([intersection - offset, np.repeat(offset, intersection.size), dst[pointed_ind]], axis=1)


def get_boundaries(a):
    return np.concatenate([[0], np.flatnonzero(a[:-1] != a[1:]) + 1, [a.size]])


def sort_using_first(arrays, kind='mergesort'):
    first, *others = arrays
    sorting = np.argsort(first, kind=kind)
    yield first[sorting]
    yield from (a[sorting] for a in others)


def non_unique_in_first(arrays):
    first, *others = arrays
    mask = np.concatenate([[False], first[:-1] == first[1:], [False]])
    non_unique = mask[:-1] | mask[1:]
    first = first[non_unique]
    return get_boundaries(first), itertools.chain([first], (a[non_unique] for a in others))


def tree_distance_threshold(o0, o1, o2t):
    """
    Compute the minimum distance threshold between nodes from a binary tree.

    :param o0: first offset
    :param o1: second offset
    :param o2t: mapping from offsets to thresholds, computed from `chains.distance_threshold`
    """
    return max(o2t[o0], o2t[o1], abs(o1 - o0) + POINTER_SIZE, 2 * POINTER_SIZE + 1)


def one_higher(trees, ptrs, o2t):
    res = defaultdict(dict)
    for offsets, trees_dict in trees.items():
        o0, o1 = offsets
        threshold = tree_distance_threshold(o0, o1, o2t)
        for mid in trees_dict:
            l, r = ptrs[mid + o0], ptrs[mid + o1]
            if l not in trees_dict or r not in trees_dict:
                continue
            nodes = snp.kway_merge(np.array([mid]), trees_dict[l], trees_dict[r], duplicates=snp.KEEP)
            if np.min(np.diff(nodes)) < threshold:
                continue
            res[offsets][mid] = nodes
    return res


def len_two_chains(offsets, pointer_set):
    res = da.from_array(offsets, 1).map_blocks(get_len2_chains, pointer_set, new_axis=1).compute()
    res = res[np.argsort(res[:, 1], kind='mergesort')]
    return sort_using_first(res.T, 'stable')


def height_one_trees(len2_chains, o2t):
    # TODO non-binary trees should make computation explode, it seems not obvious to find a solution
    boundaries, (roots, offsets, children) = non_unique_in_first(len2_chains)
    n_candidates = boundaries.size - 1
    logging.info(f'{n_candidates:,} candidate tree roots of height 1 '
                 f'(avg. {roots.size / n_candidates:,.2} links per candidate)')
    trees = defaultdict(dict)
    if roots.size == 0:
        return trees
    for a, b in pairwise(boundaries):
        mid = roots[a]
        for i in range(a, b - 1):
            offset_l = offsets[i]
            left_child = children[i]
            for j in range(i + 1, b):
                assert roots[j] == mid
                offset_r = offsets[j]
                assert offset_l < offset_r, (offset_l, offset_r)
                if abs(offset_r - offset_l) < POINTER_SIZE:
                    continue
                nodes = [mid, left_child, children[j]]
                nodes.sort()
                nodes = np.array(nodes)
                if np.min(np.diff(nodes)) < tree_distance_threshold(offset_l, offset_r, o2t):
                    continue
                trees[offset_l, offset_r][mid] = nodes
    logging.info(f'{sum(len(x) for x in trees.values()):,} 1-height binary trees ({len(trees):,} offset pairs)')
    return trees


def find_trees(offsets, pointer_set):
    o2t = {o: distance_threshold(o) for o in offsets}
    ptrs = pointer_set.to_dict()
    current_trees = height_one_trees(len_two_chains(offsets, pointer_set), o2t)
    while True:
        yield current_trees
        current_trees = one_higher(current_trees, ptrs, o2t)
        if not current_trees:
            break


def recover_nodes(root, offsets, threshold, ptrs, height=None):
    """
    Recovers the nodes of a tree.

    :param root: the root of the tree
    :param offsets: offsets at which child pointers are located
    :param threshold: distance threshold, obtained from tree_distance_threshold
    :param ptrs: pointer dictionary, obtained from `chains.PointerSet.to_dict`
    :param height: height at which to explore; if `None`, keep exploring as long as new nodes are found
    :return: a numpy array of type `POINTER_DTYPE` containing the tree's nodes
    """
    res = SortedList([root])
    parents = [root]
    for _ in range(height) if height else itertools.count():
        leaves = []
        for parent in parents:
            for o in offsets:
                try:
                    leaf = ptrs[parent + o]
                except KeyError:
                    continue
                if within_threshold(res, threshold, leaf):
                    leaves.append(leaf)
        leaves.sort()
        conflicts = set()
        for a, b in pairwise(leaves):
            if b - a < threshold:
                conflicts.add(a)
                conflicts.add(b)
        for x in leaves:
            if x not in conflicts:
                res.add(x)
        parents = leaves
    return np.fromiter(res, POINTER_DTYPE)


def main():
    global POINTER_DTYPE, POINTER_SIZE
    parser = script_utils.setup_arg_parser()
    args = parser.parse_args()
    if args.offset_step == 4:
        POINTER_DTYPE = np.uint32
        POINTER_SIZE = 4

    script_utils.setup_logging(args)
    offsets = script_utils.offsets(args)
    pointer_set = script_utils.compute_pointer_set(args)
    res = []
    for i, t in zip(itertools.count(1), find_trees(offsets, pointer_set)):
        res.append([(o, np.fromiter(d, POINTER_DTYPE)) for o, d in t.items()])
        logging.info(f'{sum(len(x) for x in t.values()):,} {i}-height binary trees ({len(t):,} offset pairs)')
    compress_pickle.dump(res, args.output)


if __name__ == '__main__':
    main()
