#!/usr/bin/env -S python3 -u

import argparse
import ctypes
import compress_pickle
import numpy as np 
import os
import script_utils

from copy import deepcopy
from elftools.elf.elffile import ELFFile
from multiprocessing import Pool 
from numpy._typing import NDArray
from objects import LinkedList, DoubleLinkedList, PointersGroup, Tree, PtrsArray, MemoryObject
from tqdm.auto import tqdm as ProgressBarIterator
from typing import Callable, Any, Counter, overload

RawDoublyLinkedLists = tuple[
    tuple[list[
        tuple[
            NDArray[np.int64], 
            np.int32, 
            NDArray[np.int64], 
            np.int32
        ]], 
        dict[np.int64,int]
    ], 
    tuple[list[
        tuple[
            NDArray[np.int64], 
            np.int32, 
            NDArray[np.int64], 
            np.int32
        ]], 
        dict[np.int64,int]
    ]
]

RawTreesRoot = list[list[
    tuple[
        tuple[np.int64, np.int64],
        NDArray[np.uint64]
    ]
]]

#######################
# Children extraction #
#######################
def build_linked_list(pointers_set:set[int]) -> LinkedList:
    linked_list = LinkedList(list(pointers_set), (0,), False)
    linked_list.determine_shape()
    linked_list.find_strings()
    return linked_list

def extract_children_linked_lists(
    cyclics: list[DoubleLinkedList],
    linears: list[DoubleLinkedList],
    trees: list[Tree],
    arrays: list[PointersGroup],
    most_common_offset: tuple[int, ...],
    pointers: dict[int,int]
    ) -> dict[str, list[LinkedList]]:
    children_linked_lists:dict[str,list[LinkedList]] = {
        'cyclics': [],
        'linears': [],
        'trees': [],
        'arrays': [] 
    }
    primitive_structures:list[tuple[str,list]] = [
        ('cyclics', cyclics),
        ('linears', linears),
        ('trees', trees),
        ('arrays', arrays)
    ]
    minimum_offset = min(most_common_offset)

    # For each primitive structure list
    for structure_name, structure_set in primitive_structures:
        print(f'Defining first level of children lists for {structure_name}...')

        children_lists_pointers:list[set[int]] = []
        lists_pointers:set[int] = set()

        # For each structure
        for structure in structure_set:
            structure: PointersGroup

            # If it's not referenced, discard
            if not structure.referenced:
                continue

            # Else, for each child offset
            for offset in structure.list_child_offsets:

                # For each near pointer
                for left_pointer in structure.near_ptrs[offset][0]:
                    lists_pointers.clear()
                    pointed = left_pointer

                    # Till we can find new valid pointers of the list
                    while True:
                        if pointed in lists_pointers:
                            break

                        # Add them
                        lists_pointers.add(pointed)
                        if pointed not in pointers:
                            break
                        pointed = pointers[pointed] + minimum_offset
                    
                    # Remove the starting pointer
                    lists_pointers.remove(left_pointer)

                    # If the list is long enough, add the list pointers
                    if len(lists_pointers) > 2:
                        children_lists_pointers.append(deepcopy(lists_pointers))

        children_lists_pointers.sort(key= lambda pointers_list: len(pointers_list), reverse= True)
        
        # Discard if no children list
        if not children_lists_pointers:
            continue

        # Discard the invalid pointers lists (intersecting ones)
        assigned_children_pointers = children_lists_pointers[0]
        lists_to_discard:list[set[int]] = []
        for children_list in children_lists_pointers[1:]:
            if assigned_children_pointers.intersection(children_list):
                lists_to_discard.append(children_list)
            else:
                assigned_children_pointers.update(children_list)
        for children_list in lists_to_discard:
            children_lists_pointers.remove(children_list)

        # Build and add the LinkedLists
        with Pool() as pool:
            linked_lists = pool.map(build_linked_list, children_lists_pointers)
            children_linked_lists[structure_name] = linked_lists
        print(f'Found {len(children_linked_lists[structure_name])} derived children linked lists')

    return children_linked_lists

######################
# Derived extraction #
######################
def derive_structures(
    primitive_structure: PointersGroup, 
    assigned_pointers: set[int],
    max_structure_size: int
    ) -> list[PointersGroup]:
    derived_structures:list[PointersGroup] = []

    for offset in primitive_structure.valid_near_offsets:

        ##############################
        # Step 1: filter out offsets #
        ##############################

        # Ignore autostructural offsets
        if offset in primitive_structure.autostructural_offsets:
            continue
        # Ignore structural offsets
        if offset in primitive_structure.structural_offsets:
            continue
        # Ignore child offsets
        if offset in primitive_structure.list_child_offsets:
            continue

        ###############################
        # Step 2: filter out pointers #
        ###############################

        pointers, null_pointers_count = primitive_structure.near_ptrs[offset]
        # Ignore short pointers collections
        if len(pointers) < 3:
            continue
        # Ignore if at there is more than 10% NULLs
        if null_pointers_count > 0.1 * len(primitive_structure.ptrs_list):
            continue
        # Ignore strings
        if pointers.intersection(primitive_structure.strs):
            continue
        # Ignore backward pointers
        if pointers.intersection(primitive_structure.ptrs_list):
            continue
        # Ignore autopointers
        if pointers.intersection(primitive_structure.autoptrs_set):
            continue
        # Ignore already assigned pointers
        if pointers.intersection(assigned_pointers):
            continue
        
        ########################################################################
        # Step 3: get the destination pointers and filter out the invalid ones #
        ########################################################################
        destination_pointers = list({
            primitive_structure.ptrs[pointer] for pointer in pointers
        })
        # Ignore short pointers collections
        if len(destination_pointers) < 3:
            continue
        # Ignore if at there is more than 10% NULLs
        if len(destination_pointers) < 0.9 * len(primitive_structure.ptrs_list):
            continue
        
        # Finally get the structure
        structure = PointersGroup(destination_pointers)
        structure.determine_shape(max_structure_size, fake=False)
        structure.find_strings()
        derived_structures.append(structure)
    return derived_structures

def extract_derived_structures(
    cyclics: list[DoubleLinkedList], 
    linears: list[DoubleLinkedList], 
    trees: list[Tree], 
    arrays: list[PointersGroup], 
    lists: list[LinkedList], 
    assigned_pointers: set[int],
    max_structure_size: int,
    external_references: set[int]
    ) -> dict[str, list[PointersGroup]]:
    derived_structures:dict[str,list[PointersGroup]] = {
        'cyclics': [],
        'linears': [],
        'trees': [],
        'arrays': [],
        'lists': [],
    }
    primitive_structures:list[tuple[str,list]] = [
        ('cyclics', cyclics),
        ('linears', linears),
        ('trees', trees),
        ('arrays', arrays),
        ('lists', lists),
    ]

    for structure_name, structure_set in primitive_structures:
        print(f'Defining first level of derived structures for {structure_name}...')

        with Pool() as pool:
            to_derive = [
                (primitive_structure, assigned_pointers, max_structure_size)
                for primitive_structure in structure_set
                if external_references.intersection(primitive_structure.ptrs_list)
            ]
            derived_structures_lists = pool.starmap(derive_structures, to_derive)
        for derived_structure_list in derived_structures_lists:
            derived_structures[structure_name].extend(derived_structure_list)
        
        print(f'Found {len(derived_structures[structure_name])} derived structures')
    return derived_structures

##########################
# LinkedLists extraction #
##########################
def extract_linked_lists(external_reference:int, most_common_offset:tuple[int, ...]) -> list[LinkedList]:
    linked_lists:list[LinkedList] = []

    # For each offset
    for offset in most_common_offset:

        # Keep track of every pointer and uniques
        pointers_list = []
        pointers_set = set()
        current_pointer = external_reference

        pointers_list.append(current_pointer)
        loop = False

        # While the pointer is in Memory, is not null and is new, then get the next pointer and cycle
        while True:
            if current_pointer not in MemoryObject.ptrs:
                break
            if MemoryObject.ptrs_is_null(current_pointer):
                break
            current_pointer = MemoryObject.ptrs[current_pointer] + offset
            if current_pointer in pointers_set:
                loop = True
                break

            pointers_list.append(current_pointer)
            pointers_set.add(current_pointer)

        # If the chain is at least 3 pointers long, we have a linked list
        if len(pointers_list) >= 3:
            linked_list = LinkedList(pointers_list, (offset,), loop)
            linked_list.determine_shape()
            linked_list.find_strings()
            if linked_list.embedded_strs.values() or linked_list.pointed_strs.values():
                linked_lists.append(linked_list)

    return linked_lists

def extract_referenced_linked_lists(pointers:dict[int,int], external_references:set[int], assigned_pointers:set[int], most_common_offset:tuple[int,...]) -> list[LinkedList]:
    print('Finding referenced linked lists...')
    linked_lists:list[LinkedList] = []

    candidates = [
        reference for reference in external_references
        if reference in pointers and reference not in assigned_pointers
    ]
    candidates_and_offset = [
        (candidate, most_common_offset) for candidate in candidates
    ]

    with Pool() as pool:
        possible_linked_lists_lists = pool.starmap(extract_linked_lists, candidates_and_offset)

    possible_linked_lists:list[LinkedList] = []
    for possible_linked_lists_list in possible_linked_lists_lists:
        possible_linked_lists.extend(possible_linked_lists_list)

    possible_linked_lists.sort(
        key=lambda linked_list: len(linked_list.ptrs_list), 
        reverse=True
    )

    visited_pointers:set[int] = set()
    for linked_list in possible_linked_lists:
        if visited_pointers.intersection(linked_list.ptrs_list):
            continue
        if assigned_pointers.intersection(linked_list.ptrs_list):
            continue
        visited_pointers.update(linked_list.ptrs_list)
        linked_lists.append(linked_list)

    print(f'Found {len(linked_lists)} linked lists')
    return linked_lists

#####################
# Arrays extraction #
#####################
def get_pointers_array_if_pointers_group(pointers_list:list[int]) -> PointersGroup|None:
    pointers_array = PtrsArray(pointers_list)
    return pointers_array.structs

def extract_pointers_arrays(pointers:dict[int,int], assigned_pointers:set[int], external_references:set[int]) -> list[PointersGroup]:
    print('Finding pointers arrays...')

    # Pointers of pointers but not autopointers nor already assigned
    autofree_pointers = {
        pointing: pointed
        for pointing, pointed in pointers.items()
        if pointing != pointed and pointing not in assigned_pointers
    }

    # Arrays of pointers
    raw_arrays_of_pointers = extract_arrays_pointers(
        autofree_pointers,
        cpu_features
    )

    # PointersGroups of those arrays if valid PointersGroup
    # filtering out the externally referenced ones
    with Pool() as pool:
        arrays_of_pointers = pool.map(
            get_pointers_array_if_pointers_group,
            filter(
                lambda pointers_list: external_references.intersection(pointers_list), 
                raw_arrays_of_pointers
            )
        )
    
    # Take only the valid PointersGroups
    arrays_of_pointers = [
        array_of_pointers for array_of_pointers in arrays_of_pointers
        if array_of_pointers is not None
    ]

    print(f'Found {len(arrays_of_pointers)} arrays of pointers')
    return arrays_of_pointers

def extract_arrays_pointers(pointers:set[int]|dict[int,int], cpu_features:dict[str,Any]) -> list[list[int]]:
    pointers_arrays = []
    ordered_pointers = sorted(pointers)

    for alignment in range(cpu_features['pointer_size']):
        keys:NDArray[np.uint32|np.uint64] = np.array([
            pointer for pointer in ordered_pointers
            if pointer % cpu_features['pointer_size'] == alignment
        ], dtype=cpu_features['numpy_uint_type'])
        diff_keys_groups = np.split(
            keys,
            np.where(np.diff(keys) != cpu_features['pointer_size'])[0] + 1
        )

        for keys_group in ProgressBarIterator(diff_keys_groups):
            if len(keys_group) < 3:
                continue
            keys_group = [cpu_features['uint_conversion_function'](key) for key in keys_group]
            pointers_arrays.append(keys_group)

    return pointers_arrays

#############################
# Strings arrays extraction #
#############################
def extract_strings_arrays(pointers:dict[int,int], strings:dict[int,str], cpu_features:dict[str,Any]) -> list[PtrsArray]:
    print('Finding arrays of strings...')
    
    # Define first strings candidates
    candidates = {
        pointer for pointer in pointers
        if pointers[pointer] in strings
    }

    strings_arrays = [
        PtrsArray(pointers_list)
        for pointers_list in extract_arrays_pointers(
            candidates,
            cpu_features
        )
    ]

    print(f'Found {len(strings_arrays)} arrays of strings')
    return strings_arrays

####################
# Trees extraction #
####################
@overload
def get_shape_and_strings(structure_object:Tree) -> Tree:
    structure_object.determine_shape()
    structure_object.find_strings()
    return structure_object

def get_tree_nodes(root:np.uint64, pointers:dict[int,int], offsets:tuple[np.int64,np.int64], levels:int) -> list[int|None]:
    """
    Returns the pointers as tree nodes
    """
    
    # elements list will contain every tree pointer
    elements:list[int|None] = [int(root)]
    converted_offsets = [int(np.int32(offset)) for offset in offsets]
    new_elements = []

    # For each level of depth
    for level in range(levels + 1):

        # Reset new elements
        new_elements.clear()

        # For each new element in the new subtree (given by level)
        for new_element in elements[2 ** level - 1:]:

            # No root, append two terminating leaves as children
            if new_element is None:
                elements.append(None)
                elements.append(None)
                continue

            # Otherwhise we have a subtree
            # For each offset
            for offset in converted_offsets:

                # If we have the corresponding pointer, we add the corresponding children
                if (new_element + offset) in pointers:
                    new_elements.append(pointers[new_element + offset])
                    continue

                # Else, we add another terminating null leaf
                new_elements.append(None)

        # Obviously, if we have no subroot, we have no subtree, hence quit
        if all([element is None for element in new_elements]):
            break

        # If we have subtrees, add them
        elements.extend(new_elements)
    return elements

def extract_trees(tree_roots_raw:RawTreesRoot, pointers:dict[int,int], assigned_pointers:set[int]) -> list[Tree]:
    #############################
    # Step 1: Extract the trees #
    #############################
    print('Converting trees...')
    trees_lists:list[list[Tree]] = []
    
    # For each tree level and associated level list
    for level, level_list in enumerate(tree_roots_raw[1:], start=2):
        new_trees:list[Tree] = []

        # For each couple of root-offsets
        for offsets, roots in level_list:
            for root in roots:
                root:np.uint64

                # Get the tree nodes as an array
                nodes = get_tree_nodes(root, pointers, offsets, level)
                
                # If it is a valid tree, append to new_trees
                try:
                    new_trees.append(
                        Tree(
                            nodes,
                            tuple(sorted(offsets, key=lambda x: int(x))),
                            level
                        )
                    )
                except RecursionError:
                    print('[!] Loop detected')

        # Append the new trees
        trees_lists.append(new_trees)

    ######################################################
    # Step 2: Remove tree with already assigned pointers #
    ######################################################
    print('Removing trees with already assigned pointers...')
    filtered_trees_list:list[list[Tree]] = []

    # For each tree list
    for trees_list in trees_lists:
        filtered_trees:list[Tree] = []

        # For each tree
        for tree in trees_list:

            # Remove the ones that uses already assigned pointers (i.e. append valid ones only)
            if not assigned_pointers.intersection(tree.ptrs_list):
                filtered_trees.append(tree)
        filtered_trees_list.append(filtered_trees)

    #############################
    # Step 3: Deduplicate trees #
    #############################
    print('Deduplicating trees...')
    reduced_trees_list:list[list[Tree]] = []

    # Invert the trees so that higher trees comes before lower trees
    filtered_trees_list.reverse()

    # For each tree_list
    for index, trees_list in enumerate(filtered_trees_list):
        reduced_trees:list[Tree] = []

        # For each tree
        for tree in trees_list:

            # Add the tree to the reduced ones
            reduced_trees.append(tree)

            # Retrieve used pointers
            tree_pointers = set(tree.ptrs_list)

            # Remove every subsequent (lower) tree from trees_lists if they share pointers with the actual tree (higher)
            for sub_index in range(index + 1, len(filtered_trees_list)):
                filtered_trees_list[sub_index] = [
                    sub_trees_list for sub_trees_list in filtered_trees_list[sub_index]
                    if not tree_pointers.intersection(sub_trees_list.ptrs_list)
                ]
        reduced_trees_list.append(reduced_trees)
    reduced_trees_list.reverse()

    #####################################
    # Step 4: Define shapes and strings #
    #####################################
    print('Defining shapes and finding strings in trees...')
    final_trees:list[Tree] = []

    # Get shape and string for each tree
    with Pool() as pool:
        for tree_list in reduced_trees_list:
            if not tree_list:
                continue
            shaped_tree_list = pool.imap(get_shape_and_strings, tree_list)
            final_trees.extend(shaped_tree_list)

    ###########################################################
    # Step 5: Get the most common trees by most common offset #
    ###########################################################
    final_trees.sort(key=lambda tree: tree.levels, reverse=True)
    most_common_trees_offsets = Counter([
        tree.dests_offsets for tree in final_trees
        if tree.levels == final_trees[0].levels    
    ]).most_common(1)[0][0]
    most_common_trees = [
        tree for tree in final_trees
        if tree.dests_offsets == most_common_trees_offsets
    ]
    most_common_trees.sort(key=lambda tree: tree.levels, reverse=True)
    print(f'Most common offset in trees: {most_common_trees_offsets}, {len(most_common_trees)}/{len(final_trees)}')

    return most_common_trees

################################
# DoublyLinkedLists extraction #
################################
def differentiate_cyclic_linear_doubly_linked_lists(doubly_linked_lists:list[DoubleLinkedList]) -> tuple[list[DoubleLinkedList], list[DoubleLinkedList]]:
    cyclics = []
    linears = []

    for doubly_linked_list in doubly_linked_lists:
        if doubly_linked_list.is_ciclic:
            cyclics.append(doubly_linked_list)
        else:
            linears.append(doubly_linked_list)
    return cyclics, linears

@overload
def get_shape_and_strings(structure_object:DoubleLinkedList) -> DoubleLinkedList:
    structure_object.determine_shape()
    structure_object.find_strings()
    return structure_object

def extract_linear_cyclic_doubly_linked_lists(doubly_linked_lists_raw:RawDoublyLinkedLists, uint_conversion_function:Callable[[int],int]) -> tuple[list[DoubleLinkedList], set[int], tuple[int, ...]]:
    """
    Extracts linear and cyclic doubly linked lists.
    Returns:
        - A list of DoublyLinkedLists
        - A set of assigned pointers
        - The most common offset
    """
    
    ############################################
    # Step 1: Extract every doubly linked list #
    ############################################
    
    # Define dict of doubly linked lists and the total
    doubly_linked_lists:dict[tuple[int, ...],list[DoubleLinkedList]] = dict()
    total_doubly_linked_lists = 0

    # Extract linear doubly linked lists
    for list_ in doubly_linked_lists_raw[0][0]:
        linear = DoubleLinkedList(
            [uint_conversion_function(i) for i in list_[0]],
            [uint_conversion_function(i) for i in list_[2]],
            (list_[1], list_[3]),
            False
        )
        sorted_structural_offsets = tuple(sorted(linear.structural_offsets))
        if not sorted_structural_offsets in doubly_linked_lists.keys():
            doubly_linked_lists[sorted_structural_offsets] = list()
        doubly_linked_lists[sorted_structural_offsets].append(linear)
        total_doubly_linked_lists += 1
    
    # Extract cyclic doubly linked lists
    for list_ in doubly_linked_lists_raw[1][0]:
        cyclic = DoubleLinkedList(
            [uint_conversion_function(i) for i in list_[0]],
            [uint_conversion_function(i) for i in list_[2]],
            (list_[1], list_[3]),
            True
        )
        sorted_structural_offsets = tuple(sorted(cyclic.structural_offsets))
        if not sorted_structural_offsets in doubly_linked_lists.keys():
            doubly_linked_lists[sorted_structural_offsets] = list()
        doubly_linked_lists[sorted_structural_offsets].append(cyclic)
        total_doubly_linked_lists += 1

    print(f'Total doubly linked lists: {total_doubly_linked_lists}')
    
    ############################################################################
    # Step 2: Reconstruct relations between cicles and remove degenerates ones #
    ############################################################################
    print('Reconstructing relations between cicles...')

    # Filter out degenerate doubly linked lists
    # Degenerates are those dll whose structs have different distances between prev and next pointers (check `objects.py` for more)
    not_degenerate:dict[tuple[int, ...],list[DoubleLinkedList]] = dict()
    for offset in doubly_linked_lists.keys():
        not_degenerate[offset] = [
            doubly_linked_list for doubly_linked_list in doubly_linked_lists[offset]
            if not doubly_linked_list.is_degenerate
        ]

    #########################################################################
    # Step 3: Get the most common doubly linked lists by most common offset #
    #########################################################################
    most_common_offset = sorted([
        (len(doubly_linked_lists_by_offset), offset) for offset, doubly_linked_lists_by_offset in not_degenerate.items()
    ], reverse=True)[0][1]
    most_common_doubly_linked_lists = not_degenerate[most_common_offset]
    most_common_doubly_linked_lists.sort(
        key=lambda doubly_linked_list: len(doubly_linked_list.ptrs_list),
        reverse= True
    )
    print(f'Most common offset in cicles: {most_common_offset}, {len(most_common_doubly_linked_lists)}/{sum([len(doubly_linked_lists_) for doubly_linked_lists_ in doubly_linked_lists.values()])}')
    
    ######################################
    # Step 4: Register assigned pointers #
    ######################################
    assigned_pointers:list[int] = []
    for doubly_linked_list in most_common_doubly_linked_lists:
        assigned_pointers.extend(doubly_linked_list.ptrs_list)
        assigned_pointers.extend(doubly_linked_list.ptrs_list_back)
    unique_assigned_pointers = set(assigned_pointers)

    #####################################
    # Step 5: Define shapes and strings #
    #####################################
    print(f'Defining linear/cyclic doubly linked lists shapes and strings...')
    with Pool() as pool:
        most_common_doubly_linked_lists = pool.map(get_shape_and_strings, most_common_doubly_linked_lists)
    
    return most_common_doubly_linked_lists, unique_assigned_pointers, most_common_offset

################
# Working data #
################
def load_data_files(dataset_directory:str) -> dict[str, Any]:
    """
    Loads data files from the dataset directory.
    The returned dictionary has the following keys and types:
        - pointers: dict[int, tuple[int, int]]
        - virtual_to_offset: addrspaces.IMOffsets
        - bitmap: bitarray.bitarray
        - strings: dict[int, str]
        - doubly_linked_lists_raw: RawDoublyLinkedLists
        - trees_roots_raw: RawTreesRoot
        - external_references: set[int]
        - functions: set[int]
    """
    
    print('Loading data files...')
    # Load data files
    pointers = compress_pickle.load(os.path.join(dataset_directory, 'extracted_ptrs.lzma'))
    strings = compress_pickle.load(os.path.join(dataset_directory, 'extracted_strs.lzma'))
    external_references = set([
        reference for reference in set(compress_pickle.load(os.path.join(dataset_directory, 'extracted_xrefs.lzma'))) 
        if reference in pointers and reference not in strings
    ])
    functions = set(compress_pickle.load(os.path.join(dataset_directory, 'extracted_functions.lzma')))

    return {
        'pointers': pointers,
        'virtual_to_offsets': compress_pickle.load(os.path.join(dataset_directory, 'extracted_v2o.lzma')),
        'bitmap': compress_pickle.load(os.path.join(dataset_directory, 'extracted_btm.lzma')),
        'strings': strings,
        'doubly_linked_lists_raw': compress_pickle.load(os.path.join(dataset_directory, 'dll.lzma')),
        'trees_roots_raw': compress_pickle.load(os.path.join(dataset_directory, 'trees.lzma')),
        'external_references': external_references,
        'functions': functions
    }

def get_cpu_features(elf_filename:str, max_size:None|int) -> dict[str, Any]:
    # Load the elf file object
    print('Defining CPU features...')
    with open(elf_filename, 'rb') as file:
        elf_file = ELFFile(file)
    
    # Based on the machine architecture, define the results
    if '386' in elf_file.get_machine_arch():
        features = {
            'uint_conversion_function': lambda x: ctypes.c_uint32(x).value,
            'int_conversion_function': lambda x: ctypes.c_int32(x).value,
            'pointer_size': 4,
            'max_structure_size': 4096,
            'numpy_uint_type': np.uint32
        }
    else:
        features = {
            'uint_conversion_function': lambda x: ctypes.c_uint64(x).value,
            'int_conversion_function': lambda x: ctypes.c_int64(x).value,
            'pointer_size': 8,
            'max_structure_size': 8192,
            'numpy_uint_type': np.uint64
        }
    if max_size is not None:
        features['max_structure_size'] = max_size
    return features

def parse_arguments() -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument('elf_file', type=str, help='The virtual machine ELF dump file')
    parser.add_argument('dataset', type=str, help='Dataset directory. The directory must contain the results from the `extract_features.py` script (extracted_xxx.lzma), the result from the `trees.py` script (trees.lzma) and the result from `bdh_doubly_linked_lists.py` script (dll.lzma)')
    parser.add_argument('-max_size', type=int, default=None, help='Maximum structure size. If not specified, it is automatically defined')
    parser.add_argument('-debug', action='store_true', default=False)
    return script_utils._get_dict_arguments(parser)

def get_shape_and_strings(structure_object:PointersGroup) -> PointersGroup:
    structure_object.determine_shape()
    structure_object.find_strings()
    return structure_object

if __name__ == '__main__':
    # Parse arguments
    arguments = parse_arguments()
    
    # Get CPU features
    cpu_features = get_cpu_features(arguments['elf_file'], arguments['max_size'])

    # Load data files
    data_files = load_data_files(arguments['dataset'])

    # Prepare MemoryObject class
    MemoryObject.prepare(
        data_files['pointers'],
        cpu_features['pointer_size'],
        data_files['virtual_to_offsets'],
        data_files['bitmap'],
        data_files['strings'],
        data_files['external_references'],
        data_files['functions'],
        arguments['elf_file']
    )

    # Get most common doubly linked lists and the first set of assigned pointers
    doubly_linked_lists, assigned_pointers, most_common_offset = extract_linear_cyclic_doubly_linked_lists(
        data_files['doubly_linked_lists_raw'],
        cpu_features['uint_conversion_function']
    )

    # Differentiate the doubly linked lists by linearity
    cyclic_doubly_linked_lists, linear_doubly_linked_lists = differentiate_cyclic_linear_doubly_linked_lists(doubly_linked_lists)

    # Get the most common trees
    trees = extract_trees(
        data_files['trees_roots_raw'],
        data_files['pointers'],
        assigned_pointers
    )

    # Get arrays of strings
    strings_arrays = extract_strings_arrays(
        data_files['pointers'],
        data_files['strings'],
        cpu_features
    )

    # Get arrays of pointers
    arrays_of_pointers = extract_pointers_arrays(
        data_files['pointers'],
        assigned_pointers,
        data_files['external_references']
    )

    # Get linked lists
    linked_lists = extract_referenced_linked_lists(
        data_files['pointers'],
        data_files['external_references'],
        assigned_pointers,
        most_common_offset
    )

    # Get derived structures
    derived_structures = extract_derived_structures(
        cyclic_doubly_linked_lists,
        linear_doubly_linked_lists,
        trees,
        arrays_of_pointers,
        linked_lists,
        assigned_pointers,
        cpu_features['max_structure_size'],
        data_files['external_references']
    )

    # Get children linked lists
    children_linked_lists = extract_children_linked_lists(
        cyclic_doubly_linked_lists,
        linear_doubly_linked_lists,
        trees,
        arrays_of_pointers,
        most_common_offset,
        data_files['pointers']
    )

    print('Saving results...')
    compress_pickle.dump({
        'trees': trees,
        'cyclics': cyclic_doubly_linked_lists,
        'linears': linear_doubly_linked_lists,
        'array_strings': strings_arrays,
        'arrays': arrays_of_pointers,
        'lists': linked_lists,
        'derived': derived_structures,
        'children': children_linked_lists
    }, os.path.join(arguments['dataset'], 'results.lzma'))