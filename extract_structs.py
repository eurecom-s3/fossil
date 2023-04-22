#!/usr/bin/env python3

import argparse
from bisect import bisect_left, bisect_right
from copy import deepcopy
from multiprocessing.dummy import Array
from os import listdir
from os.path import isfile, join
from compress_pickle import load as load_c 
from compress_pickle import dump as dump_c
import ctypes
from tqdm.auto import trange, tqdm
from collections import Counter, defaultdict 
import utils
import numpy as np 
import sortednp as snp
from trees import tree_elements, tree_elements_breadth 
from multiprocessing import Pool 
from pickle import dump 
from itertools import chain
from IPython import embed
from objects import LinkedList, DoubleLinkedList, PointersGroup, Tree, PtrsArray, MemoryObject
from elftools.elf.elffile import ELFFile
import glob, os
from itertools import chain
from sortedcontainers import SortedSet
import cProfile
from typing import Dict, List, Any, Set
import networkx as nx
from tqdm.contrib.concurrent import process_map
from statistics import mode

convf = None
aconvf = None
ptr_size = None
max_size = None
ptrs_keysa = None
top_offset = (0,0)
already_assigned = []


def convert_linear_cicles(dlists_raw):
    """Extract linear and cicles dll, convert addresses and create associated objects"""
    cicles = defaultdict(list)
    total = 0
    for l in dlists_raw[0][0]:
        lin = DoubleLinkedList([convf(i) for i in l[0]], [convf(i) for i in l[2]], (l[1],l[3]), False)
        cicles[tuple(sorted(lin.structural_offsets))].append(lin)
        total += 1

    for l in dlists_raw[1][0]:
        dll = DoubleLinkedList([convf(i) for i in l[0]], [convf(i) for i in l[2]], (l[1], l[3]), True)
        cicles[tuple(sorted(dll.structural_offsets))].append(dll)
        total += 1

    print(f"Total double linked lists: {total}")
    return cicles

def convert_trees(trees_raw, ptrs):
    """Expand trees and convert addresses"""
    trees = []

    ptrs_int = ptrs # {aconvf(k):aconvf(v) for k,v in ptrs.items()}

    for level, level_l in enumerate(trees_raw[1:], start=2):
        trees.append([])
        for offsets, roots in level_l:
            for root in roots:
                elems = tree_elements_breadth(root, ptrs_int, offsets, level)
                try:
                    trees[-1].append(Tree(elems, tuple(sorted(offsets)), level))
                except RecursionError: 
                    print("Loop detected")
    return trees

def remove_trees(trees):
    reduced_trees = []
    trees.reverse()
    for idx, level_trees in enumerate(trees):
        reduced_trees.append([])
        for tree in level_trees:
            reduced_trees[-1].append(tree)
            tree_s = set(tree.ptrs_list)
            for idx_sub in range(idx+1, len(trees)):
                trees[idx_sub] = [x for x in trees[idx_sub] if not tree_s.intersection(x.ptrs_list)]
    reduced_trees.reverse()
    return reduced_trees

def find_ptrs_arrays(ptrs):
    ptrs_arrays = []
    ptrs = sorted(ptrs)

    for align in range(ptr_size):
        keys = np.array([x for x in ptrs if x % ptr_size == align], dtype=np_type)
        diff_keys_groups = np.split(keys, np.where(np.diff(keys) != ptr_size)[0]+1)

        for group in tqdm(diff_keys_groups):
            if len(group) < 3:
                continue
            
            group = [convf(i) for i in group] # numpy :/
            ptrs_arrays.append(group)
    return ptrs_arrays

def determine_unique_cicles(sibling_list, threshold=0.9):
    """
    Determine if cicles that have the same structure size are in reality the same cicle
    """
    sibling_list.sort(key=lambda x: len(x.ptrs_list), reverse=True)
    sibling_heads = [{x + y.shape[0] for x in y.ptrs_list} for y in sibling_list]
    sibling_diffs = [set(np.diff(np.array(x.ptrs_list))) for x in sibling_list]
    already_removed = set()
    unique_structs = []

    for idx_major, sibling_major in enumerate(sibling_list):
        if sibling_major in already_removed:
            continue
        unique_structs.append([sibling_major])
        for idx_minor, sibling_minor in enumerate(sibling_list[idx_major+1:], start=idx_major+1):
                if not len(sibling_heads[idx_major].intersection(sibling_heads[idx_minor])) >= min(len(sibling_heads[idx_minor]) * threshold, len(sibling_heads[idx_minor]) -1) or \
                not sibling_diffs[idx_major].intersection(sibling_diffs[idx_minor]):
                    continue
                else:
                    already_removed.add(sibling_minor)
                    unique_structs[-1].append(sibling_minor)

    return unique_structs

def shape_string(x):
    x.determine_shape(fake=False)
    x.find_strings()
    # x.find_timestamps() 
    # x.find_ips()  
    return x

def characterize_list(x):
    x = LinkedList(list(x), (0,), False)
    x.determine_shape(fake=False)
    x.find_strings()
    # x.find_timestamps() 
    # x.find_ips()  
    return x

def define_array_obj(x):
    x = PtrsArray(x)
    if x.structs:
        # x.structs.find_ips()
        return x

def find_lists(xref):
    linked_lists = []

    for offset in top_offset:
        ptr_list = []
        ptr_set = set()
        current_ptr = xref
        ptr_list.append(current_ptr)
        loop = False
        while True:
            if current_ptr not in MemoryObject.ptrs or MemoryObject.ptrs_is_null(current_ptr):
                break
            current_ptr = MemoryObject.ptrs[current_ptr] + offset
            if current_ptr in ptr_set:
                loop = True
                break
            ptr_list.append(current_ptr)
            ptr_set.add(current_ptr)

        if len(ptr_list) >= 3:
            ll = LinkedList(ptr_list, (offset,), loop)
            ll.determine_shape()
            ll.find_strings()
            # ll.find_ips()  
            if ll.embedded_strs.values() or ll.pointed_strs.values():
                linked_lists.append(ll)
    
    return linked_lists

def derive_structs(x: PointersGroup):
    derived = []

    sorted_ptrs_list = sorted(x.ptrs_list)

    for offset in x.valid_near_offsets:
        
        # Ignore autostructural offsets and structural ones
        if offset in x.autostructural_offsets or offset in x.structural_offsets or offset in x.list_child_offsets:
            continue

        ptrs, nulls_count = x.near_ptrs[offset]

        # Ignore few pointers collections
        if len(ptrs) < 3:
            continue

        # Ignore if at there is more than 10% NULLs
        if nulls_count > 0.1 * len(x.ptrs_list):
            continue

        # Ignore strings
        if ptrs.intersection(x.strs):
            continue

        # Ignore backward pointers
        if ptrs.intersection(x.ptrs_list):
            continue

        # Ignore autopointers
        if ptrs.intersection(x.autoptrs_set):
            continue
        
        # Ignore already assigned pointers
        if ptrs.intersection(already_assigned):
            continue
        
        # Take pointer destinations 
        ptrs = list({x.ptrs[y] for y in ptrs})
        if len(ptrs) < 3 or len(ptrs) < 0.9 * len(x.ptrs_list):
            continue

        # Ignore if pointer if one of the pointers' destinations is in one of the
        # parent atomic struct
        # try:
        #     for ptr in ptrs:
        #         if (idx := bisect_left(sorted_ptrs_list, ptr)) == len(sorted_ptrs_list):
        #             raise
        #         low = sorted_ptrs_list[idx] + x.shape[0]
        #         if low <= ptr < low + x.shape[1]:
        #             raise
        # except:
        #     continue
        
        s = PointersGroup(ptrs)
        s.parent = x

        s.determine_shape(max_size, fake=False)
        s.find_strings()
        # x.find_timestamps()
        # x.find_ips()
        # if s.embedded_strs or s.pointed_strs:
        derived.append(s)
    return derived

def main():
    global convf
    global aconvf
    global ptr_size
    global np_type
    global max_size
    global ptrs_keysa
    global already_assigned
    global top_offset

    parser = argparse.ArgumentParser()
    parser.add_argument('data_dir', type=str, help='Dataset directory')
    parser.add_argument("-max_size", type=int, default=8192, help="Maximum structure size")
    parser.add_argument("-debug", action="store_true", default=False)
    args = parser.parse_args()

    # Brutal, based on extension
    print("Determine CPU features...")
    elf_filename = glob.glob(args.data_dir + "*.elf")
    with open(list(elf_filename)[0], "rb") as f:
        elffile = ELFFile(f)
        if elffile.get_machine_arch() == 'x86': #  TODO: support other arch
            convf = lambda x: ctypes.c_uint32(x).value
            aconvf = lambda x: ctypes.c_int32(x).value
            ptr_size = 4
            max_size = 4096
            np_type = np.uint32
        else:
            convf = lambda x: ctypes.c_uint64(x).value
            aconvf = lambda x: ctypes.c_int64(x).value
            ptr_size = 8
            max_size = 8192
            np_type = np.uint64

    if args.max_size:
        max_size = args.max_size

    # Load datafiles
    print("Load data files...")
    elf_filename = list(elf_filename)[0]
    ptrs = load_c(args.data_dir + "/extracted_ptrs.lzma")
    v2o = load_c(args.data_dir + "/extracted_v2o.lzma")
    btm = load_c(args.data_dir + "/extracted_btm.lzma")
    # rptrs = load_c(args.data_dir + "/extracted_rptrs.lzma")
    strings = load_c(args.data_dir + "/extracted_strs.lzma")
    dlists_raw = load_c(args.data_dir + "/dll.lzma")
    roots_raw = load_c(args.data_dir + "/trees.lzma")
    xrefs = [x for x in set(load_c(args.data_dir + "/extracted_xrefs.lzma")) if x in ptrs and x not in strings] # Consider Pointers only
    xrefs = set(xrefs)
    functions = set(load_c(args.data_dir + "/extracted_functions.lzma"))

    # Prepare MemoryObject class
    MemoryObject.prepare(ptrs, ptr_size, v2o, btm, strings, xrefs, functions, elf_filename)

    # Extract linear and cicles
    print("Convert linear and cicles double linked lists...")
    cicles = convert_linear_cicles(dlists_raw)

    print("Reconstruct relations among cicles...")
    not_degenerate = {}
    for offset in cicles.keys():
        not_degenerate[offset] = [x for x in cicles[offset] if not x.is_degenerate]
    
    top_offset = sorted([(len(l),k) for k,l in not_degenerate.items()], reverse=True)[0][1] 
    top_dlink = not_degenerate[top_offset]
    top_dlink.sort(key=lambda x: len(x.ptrs_list), reverse=True)
    print(f"Top offset in cicles: {top_offset}, {len(top_dlink)}/{sum([len(x) for x in cicles.values()])}")
    
    for dlist in top_dlink:
        already_assigned.extend(dlist.ptrs_list)
        already_assigned.extend(dlist.ptrs_list_back)
    already_assigned = set(already_assigned)
    print("Determine linear/cicle double linked lists shapes and strings...")
    with Pool() as pool:
        top_dlink = pool.map(shape_string, top_dlink)

    # Convert trees (only trees with at least 2 levels)
    print("Convert trees...")
    trees = convert_trees(roots_raw, ptrs)

    # Remove trees with already assigned elements
    trees_tmp = []
    for trees_l in trees:
        trees_tmp.append([])
        for tree in trees_l:
            if not already_assigned.intersection(tree.ptrs_list):
                trees_tmp[-1].append(tree)

    print("Deduplicate trees...")
    trees = remove_trees(trees_tmp)

    print("Determine shape and find strings in trees...")
    final_trees = []
    with Pool() as pool:
        for trees_l in trees:
            if not trees_l:
                continue
            res = pool.map(shape_string, trees_l)
            final_trees.extend(res)
    
    final_trees.sort(key=lambda x: x.levels, reverse=True)

    # weighted_offsets = []
    # for x in final_trees:
    #     weighted_offsets.extend([x.dests_offsets] * 2**x.levels)

    top_offset_trees = Counter([x.dests_offsets for x in final_trees if x.levels == final_trees[0].levels]).most_common(1)[0][0] #Counter(weighted_offsets).most_common(1)[0][0] #Counter([x.dests_offsets for x in final_trees]).most_common(1)[0][0]
    top_trees = [x for x in final_trees if x.dests_offsets == top_offset_trees]
    top_trees.sort(key=lambda x: x.levels, reverse=True)
    print(f"Top offset in trees: {top_offset_trees}, {len(top_trees)}/{len(final_trees)}")
    trees = top_trees
    
    print("Find array of strings...")
    candidates = {x for x in ptrs if ptrs[x] in strings}
    strings_arrays = [PtrsArray(x) for x in find_ptrs_arrays(candidates)]
    print(f"Found {len(strings_arrays)} arrays of strings")

    # Slow.. (OOM for haiku)
    print("Find pointers arrays...")
    ptrs_autofree = {k:v for k,v in ptrs.items() if k != v and k not in already_assigned}
    ptrs_arrays_raw = find_ptrs_arrays(ptrs_autofree)
    
    # print("Determine size of structs pointed by an array of pointers")
    with Pool() as pool:
        ptrs_array = pool.map(define_array_obj, filter(lambda x:xrefs.intersection(x), ptrs_arrays_raw))
    ptrs_array = list(filter(lambda x: x is not None, ptrs_array))
    print(f"Found {len(ptrs_array)} arrays of pointers")

    print("Find referenced linked lists...")
    linked_lists = []
    # Find possbile near pointers to XREFs ones
    candidates_list = [x for x in xrefs if x in ptrs and x not in already_assigned]
    with Pool() as pool:
        l = pool.map(find_lists, candidates_list)
    linked_lists = []
    
    tmp = []
    for i in l:
        tmp.extend(i)

    tmp.sort(key=lambda x: len(x.ptrs_list), reverse=True)
    already_visited = set()
    for i in tmp:
        if already_visited.intersection(i.ptrs_list):
            continue
        if already_assigned.intersection(i.ptrs_list):
            continue
        already_visited.update(i.ptrs_list)
        linked_lists.append(i)

    print(f"Found {len(linked_lists)} linked lists")

    cicles = []
    linears = []
    for i in top_dlink:
        if i.is_ciclic:
            cicles.append(i)
        else:
            linears.append(i)

    derived = {"cicles": [[],[]], "linears": [[],[]], "trees": [[],[]], "arrays": [[],[]], "lists": [[],[]]} 

    for struct_set, struct_name in [(cicles, "cicles"), (linears, "linears"), (trees, "trees"), ([x.structs for x in ptrs_array], "arrays"), (linked_lists, "lists")]:
        print(f"Determine first level derived structures for {struct_name}...")
        with Pool() as pool:
            d = pool.map(derive_structs, filter(lambda x: xrefs.intersection(x.ptrs_list), struct_set))
        for dd in d:
            derived[struct_name][0].extend(dd)
        print(f"Found {len(derived[struct_name][0])} derived structures")

        # print(f"Determine second level derived structures for {struct_name}...")
        # with Pool() as pool:
        #     d = pool.map(derive_structs, derived[struct_name][0])
        # for dd in d:
        #     derived[struct_name][1].extend(dd)
        # print(f"Found {len(derived[struct_name][1])} derived structures")

    # Extract children lists
    children = {"cicles": [], "linears": [], "trees": [], "arrays": []}
    offset_min = min(top_offset)
    for struct_set, struct_name in [(cicles, "cicles"), (linears, "linears"), (trees, "trees"), ([x.structs for x in ptrs_array], "arrays")]:
        print(f"Determine first level children lists for {struct_name}...")
        
        c = []
        p = set()
        for elem in struct_set:
            if not elem.referenced:
                continue
            for offset in elem.list_child_offsets:
                for l_ptr in elem.near_ptrs[offset][0]:
                    p.clear()
                    val = l_ptr
                    while True:
                        if val in p:
                            break
                        p.add(val)
                        if val not in ptrs:
                            break
                        val = ptrs[val] + offset_min
                    p.remove(l_ptr)
                    if len(p) > 2:
                        c.append(deepcopy(p))
        c.sort(key=lambda x: len(x), reverse=True)
        if not c:
            continue
        m = c[0]
        to_delete = []
        for i in c[1:]:
            if m.intersection(i):
                to_delete.append(i)
            else:
                m.update(i)

        for i in to_delete:
            c.remove(i)
        
        with Pool() as pool:
            d = pool.map(characterize_list, c)
            children[struct_name] = d
        print(f"Found {len(children[struct_name])} derived children")

    print("Saving results...")
    dump_c({"trees": trees, "cicles": cicles, "linears": linears, "arrays_strings": strings_arrays, "arrays": ptrs_array, "lists": linked_lists, "derived": derived, "children": children}, args.data_dir + "/results.lzma")

if __name__ == '__main__':
    main()