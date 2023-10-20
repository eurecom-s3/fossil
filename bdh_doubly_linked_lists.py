#!/usr/bin/env -S python3 -u
import compress_pickle
import itertools
import logging
import numpy as np
import os
import script_utils
from bdhash import BDHStack # type:ignore
from bdhash import DTYPE as BDHASH_DTYPE
from bdhash import fwd_hash
from chains import ChainGraph, PointerSet
from chains import POINTER_DTYPE, POINTER_SIZE, UNSIGNED_POINTER_DTYPE
from constants import DOUBLY_LINKED_LISTS_FILE
from dask.bag import Bag
from more_itertools import pairwise

hashes_dtype = np.dtype([('hash', BDHASH_DTYPE), ('direction', np.bool_), ('head', POINTER_DTYPE),
                         ('tail', POINTER_DTYPE), ('offset', np.int32), ('size', np.uint64)])

def parse_arguments() -> dict:
    # Get common parser and add argument
    parser = script_utils.get_parser()
    parser.add_argument('--min-size', type=int, default=3, help="minimum length of chains (default: 3)")
    return script_utils.parse_arguments(parser)

def bidirectional_hashes(graph: ChainGraph, min_size:int) -> tuple[np.ndarray, np.ndarray]:
    """
    Computes bidirectional hashes.
    Returns 2 multidimensional arrays: linear and cyclic
    """

    # Initialize data
    offset = graph.offset
    diffs_min_size = min_size - 1
    linear_results, cyclic_results = [], []
    
    # Compute search
    for cycle, rtrees in graph.component_breakdowns(min_size):
        
        # Cyclic search
        if cycle is not None:
            first_hash = fwd_hash(np.diff(cycle))
            second_hash = fwd_hash(np.diff(np.roll(cycle, -1)[::-1]))
            
            # no palindromic sequences or hash conflicts
            assert first_hash != second_hash

            hashed, direction, head, tail = (second_hash, 1, cycle[1], cycle[0])
            if first_hash < second_hash:
                hashed, direction, head, tail = (first_hash, 0, cycle[0], cycle[-1])
            
            cyclic_results.append((
                hashed, 
                direction, 
                head, 
                tail, 
                offset, 
                cycle.size
            ))

        # Linear search
        for sink, parent_mapping in rtrees:
            diffs = BDHStack()

            stack:list[tuple[int, np.int64, np.int64]]
            stack = [
                (0, sink, parent) 
                for parent in parent_mapping[sink]
            ]

            while stack:
                depth, child, parent = stack.pop()
                while len(diffs) != depth:
                    assert len(diffs) > depth
                    diffs.pop()
                
                diffs.append(child - parent)
                depth += 1
                assert depth == len(diffs)

                if depth >= diffs_min_size:
                    first_hash, second_hash = diffs.hash()

                    # fails for palindromic sequences or hash conflicts
                    assert first_hash != second_hash, list(diffs)  

                    hashed, direction = (second_hash, 1)
                    if first_hash < second_hash:
                        hashed, direction = (first_hash, 0)
                    
                    linear_results.append((
                        hashed, 
                        direction, 
                        parent, 
                        sink, 
                        offset, 
                        depth + 1
                    ))
                stack.extend(
                    (depth, parent, grandpa) 
                    for grandpa in parent_mapping.get(parent, [])
                )

    # Process results 
    linear = np.array(linear_results, hashes_dtype)
    cyclic = np.array(cyclic_results, hashes_dtype)
    linear.sort(order=('size', 'hash', 'direction'))
    cyclic.sort(order=('size', 'hash', 'direction'))

    return linear, cyclic

def get_unique_indices(array:np.ndarray) -> np.ndarray:
    """
    Returns the indices of each first unique element of the sorted array
    """

    if array.size == 0:
        return np.array([])
    mask = np.empty(array.shape, dtype=np.bool_)
    mask[0] = True
    mask[1:] = array[1:] != array[:-1]
    return np.flatnonzero(mask)

def get_parameters_boundaries(rows:np.ndarray, assigned:dict) -> list[tuple[tuple[POINTER_DTYPE,POINTER_DTYPE,POINTER_DTYPE],tuple[POINTER_DTYPE,POINTER_DTYPE]]]:
            """
            Calculates paramaters for building the chain
            Results are sorted by lowest right boundary
            The reference object is the head if direction == 0, tail otherwise.

            Returns a list with the following structure:
            - (
                (head:int, offset:int, size:int),
                (left_boundary:int, right_boundary:int)
            )
            """

            result = []
            for _, direction, head, tail, offset, size in rows:
                
                # Skip rows containing already assigned heads or tails
                if head in assigned:
                    continue
                if tail in assigned:  # skip rows containing already assigned heads or tails
                    continue

                # Get starting pointer
                pointer = head
                if direction:
                    pointer = tail

                # By subtracting the offset we get what was pointed by the previous element
                pointed = pointer - offset

                # Get the boundaries
                boundaries = (
                    pointer,
                    max(pointer + POINTER_SIZE + 1, pointed + 1)
                )
                if offset > 0:
                    boundaries = (
                        pointed,
                        pointer + POINTER_SIZE
                    )

                result.append((
                    (head, offset, size), 
                    boundaries
                ))

            # Sort the results from the lowest right boundary
            result.sort(key=lambda pair: pair[1][1])
            return result

def compute_chain(pointers: dict[POINTER_DTYPE,POINTER_DTYPE], head:POINTER_DTYPE, offset:POINTER_DTYPE, size:POINTER_DTYPE):
    """Compute a chain using the pointers dictionary."""

    result = [head]
    while len(result) < size:
        head = pointers[head] + offset
        result.append(head)
    return np.array(result, dtype=UNSIGNED_POINTER_DTYPE).astype(POINTER_DTYPE)

def compute_matches(data: np.ndarray, pointers: dict[POINTER_DTYPE, POINTER_DTYPE], label: str) -> tuple[list[tuple[np.ndarray,POINTER_DTYPE,np.ndarray,POINTER_DTYPE]], dict[POINTER_DTYPE,int]]:
    """
    Find matches from the computed hashes.
    Returns a list (matches) and a dict (assigned)
    """

    # First check
    if not len(data):
        return [], {}

    # Data sorting
    # ------------
    #   This sorting allows grouping by hash then direction
    #   We'll start from the bottom to prioritize longer lists
    #   Mergesort specifies Timsort, which is faster for almost-sorted data
    data.sort(order=('size', 'hash', 'direction'), kind='mergesort')

    # Data filtering
    # --------------
    # Take only duplicate values. See how np.unique is implemented to get how this works.
    non_unique_mask = np.concatenate([~np.diff(data['hash']).astype(bool), [False]])
    non_unique_mask |= np.roll(non_unique_mask, 1)
    data = data[non_unique_mask]

    logging.info(f'{label}: {data.size:,} non-unique hashes')
    assigned = {}
    matches = []

    # Data transformation for elaboration
    unique_hash_indices = get_unique_indices(data['hash'])
    chained_unique_indices = itertools.chain(unique_hash_indices, [None])
    paired_unique_indices = list(pairwise(chained_unique_indices))


    # We start from the bottom to give priority to longest chains
    for first_index, second_index in paired_unique_indices[::-1]:

        # This group contains all elements having the same (size, hash) pair
        group = data[first_index:second_index]
        assert len(set(group['hash'])) == 1
        assert len(set(group['size'])) == 1

        # Index discriminating between the two directions
        changing_direction_index = np.searchsorted(group['direction'], 1)

        # Hashes in just a single direction: no possible matches
        if not (0 < changing_direction_index < group.size):
            continue

        # Get forward referencing pointers
        forward = get_parameters_boundaries(group[:changing_direction_index], assigned)
        if len(forward) == 0:
            continue

        # Get backward referencing pointers
        # We use a dictionary because it preserves insertion order (by right boundary)
        backward = dict(get_parameters_boundaries(group[changing_direction_index:], assigned))
        if len(backward) == 0:
            continue

        # Get forward pointing chain
        chain = compute_chain(pointers, *forward[0][0])
        diff = np.diff(chain)
        min_diff = np.min(np.diff(np.sort(chain)))
        assert min_diff > 0

        for (forward_head, forward_offset, forward_size), (forward_left, forward_right) in forward:
            # The object must be in the interval:
            #   min(backward_left, forward_left) <= object < max(backward_right, forward_right)
            # having the interval <= min_diff
            
            # These thresholds are respectively minimum and maximum values for backward_left and backward_right
            min_threshold = forward_right - min_diff
            max_threshold = forward_left + min_diff

            candidates, to_delete = [], []
            for backward_parameters, (backward_left, backward_right) in backward.items():
                
                # Since min_threshold depends on forward_right, backward_parameters wont' match any more
                if backward_left < min_threshold:
                    to_delete.append(backward_parameters)  # we can't delete from bwd right now, since we're iterating on it
                    continue
                
                # Because of the sorting, we won't find any more matches with the forward chain
                if backward_right > max_threshold:
                    break

                candidates.append(backward_parameters)

            for backward_parameters in to_delete:
                del backward[backward_parameters]

            if not candidates:
                continue

            forward_chain = compute_chain(pointers, forward_head, forward_offset, forward_size)

            # Hash collision check
            assert np.array_equal(np.diff(forward_chain), diff)

            # Discard already assigned pointers
            if any(pointer in assigned for pointer in forward_chain):
                continue

            # Try to match candidates. Closest ones first
            forward_head = forward_chain[0]
            sorted_candidates = sorted(candidates, key=lambda params: abs(forward_head - params[0]))
            for backward_parameters in sorted_candidates:
                backward_head, backward_offset, backward_size = backward_parameters
                assert backward_size == forward_size

                backward_chain = compute_chain(pointers, backward_head, backward_offset, backward_size)

                # Hash collision check
                assert np.array_equal(np.diff(backward_chain[::-1]), diff)

                # Discard already assigned
                if any(pointer in assigned for pointer in backward_chain):
                    del backward[backward_parameters]
                    continue

                # Discard both direction pointers
                assert len(set(forward_chain) & set(backward_chain)) == 0

                # Interval size respected
                assert forward_chain[0] - backward_chain[-1] <= min_diff

                # Check correspondence between pointers (from different directions)
                assert (np.diff(forward_chain - backward_chain[::-1]) == 0).all()
                
                # Match found! Let's go!
                matches_no = len(matches)
                matches.append((forward_chain, forward_offset, backward_chain, backward_offset))

                # Assign pointers
                for chain in [backward_chain, forward_chain]:
                    for pointer in chain:
                        assigned[pointer] = matches_no
            
                # Remove backward parameters
                del backward[backward_parameters]
                break
    return matches, assigned

def search_linear_and_cyclic_matches(graphs:Bag, min_size:int, pointer_set:PointerSet):
    pointers = pointer_set.to_dict()
    bd_hashes:zip[tuple[np.ndarray,np.ndarray]] = zip(*graphs.map(bidirectional_hashes, min_size).compute())
    linear, cyclic = [
        np.concatenate(arrays) 
        for arrays in bd_hashes
    ]
    logging.info(f'hashes: {linear.size:,} (linear), {cyclic.size:,} (cyclic)')
    return compute_matches(linear, pointers, 'linear'), \
            compute_matches(cyclic, pointers, 'cyclic')

if __name__ == '__main__':
    arguments = parse_arguments()
    results = search_linear_and_cyclic_matches(arguments['graphs'], arguments['min_size'], arguments['pointers'])
    for name, (match_list, pointer_to_match) in zip(['linear', 'cycles'], results):
        matches_no = len(match_list)
        try:
            logging.info(f'{name}: {matches_no:,} lists (avg length {len(pointer_to_match) / matches_no:,.2f})')
        except ZeroDivisionError:
            logging.info('Something was wrong, 0 matches... :(')
    compress_pickle.dump(results, os.path.join(arguments['output'], DOUBLY_LINKED_LISTS_FILE))
