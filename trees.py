#!/usr/bin/env -S python3 -u
import compress_pickle
import dask.array as dask_array
import itertools
import logging
import numpy as np
import os
import script_utils
import sortednp
import sys

from chains import PointerSet
from numpy._typing import NDArray
from typing import Generator

if sys.version_info >= (3,10):
    from itertools import pairwise
else:
    from more_itertools import pairwise

def get_next_height_trees(trees:dict[tuple[np.int64,np.int64],dict[np.int64,NDArray[np.int64]]], pointers_dict:dict[np.int64,np.int64], threshold_from_offset:dict[np.int64,np.int64]) -> dict[tuple[np.int64,np.int64],dict[np.int64,NDArray[np.int64]]]:
    new_trees: dict[tuple[np.int64,np.int64],dict[np.int64,NDArray[np.int64]]] = dict()
    
    # For each tree (i.e. left/right child tuple + root nodes dict)
    #   considering left/right child as offsets
    for offsets, root_to_nodes_dict in trees.items():

        # Get left and right offsets and threshold
        left_offset, right_offset = offsets
        threshold = get_minimum_tree_distance_threshold(left_offset, right_offset, threshold_from_offset)

        # For each node
        for node in root_to_nodes_dict:

            # Get children from pointers using offsets
            left_child, right_child = pointers_dict[node + left_offset], pointers_dict[node + right_offset]

            # If any of those isn't in the nodes, no tree
            if left_child not in root_to_nodes_dict or right_child not in root_to_nodes_dict:
                continue

            # Merge the nodes into a unique tree
            nodes = sortednp.kway_merge(
                np.array([node]), 
                root_to_nodes_dict[left_child], 
                root_to_nodes_dict[right_child], 
            duplicates=sortednp.KEEP)

            # Discard if the minimum trees distance threshold is less than the minimum distance between nodes
            if np.min(np.diff(nodes)) < threshold:
                continue

            # Initialize subdict if needed
            if not offsets in new_trees.keys():
                new_trees[offsets] = dict()

            # Add the subtree
            new_trees[offsets][node] = nodes
    return new_trees

def get_minimum_tree_distance_threshold(left_offset:np.int64, right_offset:np.int64, threshold_from_offset:dict[np.int64,np.int64]) -> np.int64:
    return np.max([
        threshold_from_offset[left_offset],
        threshold_from_offset[right_offset],
        abs(right_offset - left_offset) + POINTER_SIZE,
        np.int64(2 * POINTER_SIZE + 1)
    ])

def get_chain_boundaries(chain:NDArray[np.int64]) -> NDArray[np.int64]:
    return np.concatenate([
        [0], 
        np.flatnonzero(chain[:-1] != chain[1:]) + 1, 
        [chain.size]
    ])

def get_height_one_trees_starting_data(length_two_chains_generator:Generator[NDArray[np.int64], None, None]) -> tuple[NDArray[np.int64],itertools.chain[NDArray[np.int64]]]:
    # Get chains
    first_chain, *other_chains = length_two_chains_generator
    
    # Filter for duplicated only chains (i.e. non unique)
    mask = np.concatenate([[False], first_chain[:-1] == first_chain[1:], [False]])
    duplicate_mask = mask[:-1] | mask[1:]
    first_chain = first_chain[duplicate_mask]

    return get_chain_boundaries(first_chain), \
        itertools.chain([first_chain], (chain[duplicate_mask] for chain in other_chains))

def get_height_one_trees(length_two_chains_generator:Generator[NDArray[np.int64], None, None], threshold_from_offset:dict[np.int64,np.int64]) -> dict[tuple[np.int64,np.int64],dict[np.int64,NDArray[np.int64]]]:
    """ 
    Returns trees in the following format:
    {
        (left_child, right_child): {
            root: tree
        }
    }
    """
    # TODO non-binary trees should make computation explode, it seems not obvious to find a solution
    # Get initial data
    boundaries, (roots, offsets, children) = get_height_one_trees_starting_data(length_two_chains_generator)
    candidates_no = boundaries.size - 1
    logging.info(f'{candidates_no:,} candidate tree roots of height 1 (avg. {roots.size / candidates_no:,.2} links per candidate)')
    trees: dict[tuple[np.int64,np.int64],dict[np.int64,NDArray[np.int64]]] = dict()
    
    # If no roots, no trees, return immediately
    if roots.size == 0:
        return trees

    # Check for trees
    # For each couple of boundaries
    for left_boundary, right_boundary in pairwise(boundaries):
        
        left_boundary: np.int64
        right_boundary: np.int64

        # Get the root (a)
        h1_tree_root: np.int64 = roots[left_boundary]

        # For each left pointer
        for left_pointer in range(left_boundary, right_boundary - 1):
            
            # Get left offset and child
            left_offset: np.int64 = offsets[left_pointer]
            left_child: np.int64 = children[left_pointer]

            # For each right pointer
            for right_pointer in range(left_pointer + 1, right_boundary):
                
                # Get right offset and child
                right_offset: np.int64 = offsets[right_pointer]
                right_child: np.int64 = children[right_pointer]

                # Confirm that it's the same root and that left offset is less than the right offset
                assert roots[right_pointer] == h1_tree_root
                assert left_offset < right_offset, (left_offset, right_offset)

                # Discard if no pointer can fit
                if abs(right_offset - left_offset) < POINTER_SIZE:
                    continue

                # Get the nodes of h1 tree, sort them and transform them into a numpy array
                nodes = [h1_tree_root, left_child, right_child]
                tree: NDArray[np.int64] = np.sort(nodes)

                # Discard if the minimum trees distance threshold is less than the minimum distance between nodes
                if np.min(np.diff(tree)) < get_minimum_tree_distance_threshold(left_offset, right_offset, threshold_from_offset):
                    continue

                # Initialize dict if needed
                if not (left_offset, right_offset) in trees.keys():
                    trees[left_offset, right_offset] = dict()

                # Add the tree to tress
                trees[left_offset, right_offset][h1_tree_root] = tree
    logging.info(f'{sum(len(x) for x in trees.values()):,} 1-height binary trees ({len(trees):,} offset pairs)')
    return trees

def compute_len_two_chains(encapsulated_offset: NDArray[np.int64], pointer_set: PointerSet) -> NDArray[np.int64]:
    # Get raw offset and source and destination pointers
    offset:np.int64 = encapsulated_offset[0]
    src_pointers, dst_pointers = pointer_set.src, pointer_set.dst
    
    # Filter valid pointers by checking threshold range
    in_range = abs(dst_pointers - src_pointers) >= get_distance_threshold(offset)
    src_pointers, dst_pointers = src_pointers[in_range], dst_pointers[in_range]

    # Return len_two_chains
    intersected_pointers, (src_pointers_indices, _) = sortednp.intersect(
        src_pointers, 
        dst_pointers[np.argsort(dst_pointers)] + offset, 
        indices=True
    )
    return np.stack([
        intersected_pointers - offset, 
        np.repeat(offset, intersected_pointers.size), 
        dst_pointers[src_pointers_indices]], 
    axis=1)

def get_length_two_chains_generator(offsets:NDArray[np.int64], pointer_set:PointerSet) -> Generator[NDArray[np.int64], None, None]:
    # Transform into dask array
    offsets_dask_array:dask_array.Array = \
        dask_array.from_array(offsets, '1')
    
    # Compute and get a 'len two chain' for each offset
    length_two_chains:NDArray[np.int64] = \
        dask_array.map_blocks(
            compute_len_two_chains, 
            offsets_dask_array, 
            pointer_set, 
            new_axis=1)\
        .compute()

    # Sort chains by offset values
    sorted_indices_by_offsets = np.argsort(length_two_chains[:, 1], kind='mergesort')
    length_two_chains:NDArray[np.int64] = length_two_chains[sorted_indices_by_offsets]

    # Return a sorted generator with the transpose of the chains
    first_chain, *other_chains = length_two_chains.transpose()
    sorted_indices = np.argsort(first_chain, kind='stable')
    yield first_chain[sorted_indices]
    yield from (chain[sorted_indices] for chain in other_chains)

def get_distance_threshold(offset:np.int64) -> np.int64:
    if offset > 0:
        return offset + POINTER_SIZE
    return np.max([-offset, np.int64(POINTER_SIZE)]) + 1

def find_trees(offsets:NDArray[np.int64], pointer_set:PointerSet) -> Generator[dict[tuple[np.int64,np.int64],dict[np.int64,NDArray[np.int64]]], None, None]:
    # Offset -> Threshold mapping
    threshold_from_offset:dict[np.int64,np.int64] = {offset: get_distance_threshold(offset) for offset in offsets}
    pointers_dict = pointer_set.to_dict()

    # Retrieve len two chains
    length_two_chains = get_length_two_chains_generator(offsets, pointer_set)
    current_trees = get_height_one_trees(length_two_chains, threshold_from_offset)

    while True:
        yield current_trees
        current_trees = get_next_height_trees(current_trees, pointers_dict, threshold_from_offset)
        if not current_trees:
            break

if __name__ == '__main__':
    # Parse arguments
    arguments = script_utils.parse_arguments(script_utils.get_parser())
    
    # Set pointer dtype and size
    if arguments['offset_step'] == 4:
        POINTER_DTYPE = np.uint32
        POINTER_SIZE = 4
    else:
        POINTER_DTYPE = np.uint64
        POINTER_SIZE = 8

    # Find trees
    offsets:NDArray[np.int64] = np.arange(arguments['min_offset'], arguments['max_offset'] + 1, arguments['offset_step'])
    results:list[list[tuple[tuple[np.int64,np.int64], NDArray[np.uint32|np.uint64]]]] = []
    for index, tree in zip(itertools.count(1), find_trees(offsets, arguments['pointers'])):
        results.append([
            (children, np.fromiter(root, POINTER_DTYPE)) 
            for children, root in tree.items()
        ])
        logging.info(f'{sum(len(x) for x in tree.values()):,} {index}-height binary trees ({len(tree):,} offset pairs)')
    compress_pickle.dump(results, os.path.join(arguments['output'],'trees.lzma'))
