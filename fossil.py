#!/usr/bin/env -S python3 -u

import argparse
import compress_pickle
import os
import sys


from binarytree import build as buildtree
from cmd2.ansi import style, fg, bg
from cmd2.cmd2 import Cmd
from cmd2.decorators import with_argparser, with_category
from colorama import Back, Fore
from constants import (
    DERIVED_STRUCTURES,
    RESULTS_FILE,
    STRINGS_FILE,
    POINTERS_FILE,
    INVERSE_POINTERS_FILE,
)
from constants import (
    ARRAYS_OF_POINTERS,
    ARRAYS_OF_STRINGS,
    CIRCULAR_DOUBLY_LINKED_LISTS,
    LINEAR_DOUBLY_LINKED_LISTS,
    LINKED_LISTS,
    TREES
)
from objects import PointersGroup, PtrsArray, Tree
from prettytable import PrettyTable, ALL
from statistics import mean
from typing import Any

####################
# Argument parsing #
####################
def parse_working_directory() -> str:
    parser = argparse.ArgumentParser()
    parser.add_argument('workdir', type=str, help='Directory containing extracted data')
    arguments = parser.parse_args()
    return arguments.workdir

def get_finder_parser() -> argparse.ArgumentParser:
    finder_parser = argparse.ArgumentParser()
    finder_parser.add_argument('-i',   '--include', action='store_true', help='Look for strings include this substring', default=False)
    finder_parser.add_argument('-I',   '--insensitive', action='store_true', help='Case insensitive', default=False)
    finder_parser.add_argument('-cdl', '--circular_double_linked', action='store_true', help='Look for strings in Circular Double Linked lists', default=False)
    finder_parser.add_argument('-ldl', '--linear_double_linked', action='store_true', help='Look for strings in Linear Double Linked lists', default=False)
    finder_parser.add_argument('-t',   '--trees', action='store_true', help='Look for strings in double trees', default=False)
    finder_parser.add_argument('-a',   '--arrays', action='store_true', help='Look for strings in arrays', default=False)
    finder_parser.add_argument('-as',  '--arrays_struct', action='store_true', help='Look for strings in arrays of structs', default=False)
    finder_parser.add_argument('-ds',  '--derived_structs', action='store_true', help='Look for strings in derived structs', default=False)
    finder_parser.add_argument('-l',   '--lists', action='store_true', help='Look for strings in linked lists', default=False)
    finder_parser.add_argument('-r',   '--referenced', action='store_true', help='Only referenced', default=False)
    finder_parser.add_argument('string', nargs='+', default=[], help='Strings to look for')
    return finder_parser

def get_expand_parser() -> argparse.ArgumentParser:
    expand_parser = argparse.ArgumentParser()
    expand_parser.add_argument("-cdl", "--circular_double_linked", action="store_true", help="Expand Circular Double Linked lists", default=False)
    expand_parser.add_argument("-ldl", "--linear_double_linked", action="store_true", help="Expand in Linear Double Linked lists", default=False)
    expand_parser.add_argument("-t", "--trees", action="store_true", help="Expand in double trees", default=False)
    expand_parser.add_argument("-a", "--arrays", action="store_true", help="Expand in arrays", default=False)
    expand_parser.add_argument("-as", "--arrays_struct", action="store_true", help="Expand arrays of structs", default=False)
    expand_parser.add_argument("-ds", "--derived_structs", action="store_true", help="Look for strings in derived structs", default=False)
    expand_parser.add_argument("-l", "--lists", action="store_true", help="Expand simple list", default=False)
    expand_parser.add_argument("-p", "--pointed", action="store_true", help="String is pointed")
    expand_parser.add_argument("index", type=int, help="Structure index")
    expand_parser.add_argument("offset", type=int, help="Offset in structure")
    return expand_parser

def get_zero_parser() -> argparse.ArgumentParser:
    zero_parser = argparse.ArgumentParser()
    zero_parser.add_argument("-cdl", "--circular_double_linked", action="store_true", help="Look for strings in Circular Double Linked lists", default=False)
    zero_parser.add_argument("-ldl", "--linear_double_linked", action="store_true", help="Look for strings in Linear Double Linked lists", default=False)
    zero_parser.add_argument("-t", "--trees", action="store_true", help="Look for strings in double trees", default=False)
    zero_parser.add_argument("-as", "--arrays_struct", action="store_true", help="Look for strings in arrays of structs", default=False)
    zero_parser.add_argument("-ds", "--derived_structs", action="store_true", help="Look for strings in derived structs", default=False)
    zero_parser.add_argument("-l", "--lists", action="store_true", help="Look for strings in linked lists", default=False)
    zero_parser.add_argument("-r", "--referenced", action="store_true", help="Only referenced", default=False)
    return zero_parser

class FossilShell(Cmd):
    def __init__(self, path:str):
        dinosaur = "\n\
            :ymMMmy/`\n\
            /MMMMMMMMNy/`                                                                     ```\n\
            -NMMMMMMMMMMMms-                                                       `-/+oydNNNNMMMMNmdy/.\n\
            :hMMMMMMMMMMMMMNo-`                                               ./smMMMMMMMMMMMMMMMMMMMMMmo`\n\
            :NMMMMMMMMMMMMMMMdo`                                          /hMMMMMMMMMMMMMmys+////+ohmMMNo\n\
                :mMMMMMMMMMMMMMMMMN:                                       +mMMMMMMMMMMNy+:`            `:+/\n\
                .:yMMMMMMMMMMMMMMM/                                    :mMMMMMMMMMdo-\n\
                    omMMMMMMMMMMMMMN/                                  sMMMMMMMMMh-\n\
                    +mMMMMMMMMMMMMM:                               `yMMMMMMMMm-\n\
                        oMMMMMMMMMMMMMh                              -dMMMMMMMMm.\n\
                `+ydmmMMMMMMMMMMMMMMMN`                           `sMMMMMMMMMN.\n\
            -yNMMMMMMMMMMMMMMMMMMMMN                          .sNMMMMMMMMMM/\n\
        `-hyydNMMMMMMMMMMMMMMMMMMMMMMMm                        -yMMMMMMMMMMMMy\n\
        NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN                 ./oyhdmMMMMMMMMMMMMMM:\n\
        -hmmmmdyo+/:::::+dMMMMMMMMMMMMm          `` .ohNMMMMMMMMMMMMMMMMMMMM+\n\
                        :NMMMMMMMMMMd  `/ydNNMMMMNMMMMMMMMMMMMMMMMMMMMMMMy\n\
                /+//.      oMMMMMMMMMMMmdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm`\n\
            ``.:mMMo     `mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd\n\
            odNMMdyMMMy`    :MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN`\n\
            .odMMMMMMMMd`    hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN`\n\
        `hdNMds+odMMMMd`   .mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-\n\
                `yMMMMd`   -mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM.\n\
                    `:oNMm+:. `sMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm\n\
                        .hNMMMNhosMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM+\n\
                        -hNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd`\n\
                            :oydNMMhodMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd`\n\
                            -syysso+-`  `.sMMMMMMMMMMMMMMMMMMMMMMMMMMMm.\n\
                        -dNMMNMMMMMMMNmhmMMMMMMMMMh`.-:/+o+NMMMMMMMMMMmo`\n\
                        .. `+smMMMMMMMMNddddMMMMMMM-       dMMMMMMMMMMMMNm-\n\
                            /mMMNsmMMy++-`    :dMMMMMs        sNMMMMMMMMMMMMm`\n\
                            :No-.`dMM:           +NMMMN-        `-++:-:/+sdMMMd\n\
                                /Mm+             +MMMMs                   hMMM+\n\
                                sh`            `sMMMNs`                   +MMMm\n\
                                        -oo/./mMMMy.                 :hdhhMMMh\n\
                                        yNmMMMMMMMo                  .NhdMMMMM/\n\
                                        `:yNMMMMN+                       :MMMMs\n\
                                    :shNMMMMMMM+                      .yNMMMMM.\n\
                                `sNMMMMMMMNNmh`                     :NMNNNMMd`\n\
                                yNdyyso:.`                          ./`   :-\n\
\t\t\t\t\t  ______                _  _ \n\
\t\t\t\t\t |  ____|              (_)| |\n\
\t\t\t\t\t | |__  ___   ___  ___  _ | |\n\
\t\t\t\t\t |  __|/ _ \\ / __|/ __|| || |\n\
\t\t\t\t\t | |  | (_) |\\__ \\\\__ \\| || |\n\
\t\t\t\t\t |_|   \\___/ |___/|___/|_||_|\n\
                             \n\
                             "
        Cmd.__init__(self, use_ipython=True)
        self.self_in_py = True
        self.intro      = style(dinosaur, bold=True, bg=bg(Back.BLACK), fg=fg(Fore.WHITE))
        self.prompt     = 'fossil> '

        # Hide default settings
        # self.remove_settable('debug')
        self.path       = path

        # Load results, strings, ptrs, rptrs
        self.results:          dict[str, Any] = compress_pickle.load(os.path.join(path, RESULTS_FILE))
        self.strings:          dict[int, str] = compress_pickle.load(os.path.join(path, STRINGS_FILE))
        self.pointers:         dict[int, int] = compress_pickle.load(os.path.join(path, POINTERS_FILE))
        self.reverse_pointers: dict[int, int] = compress_pickle.load(os.path.join(path, INVERSE_POINTERS_FILE))

    #####################
    # Helping functions #
    #####################
    def __discard_offsets(self, structure:PointersGroup) -> PointersGroup:
        offsets = list(structure.embedded_strs.keys())
        for offset in offsets:
            strings = [
                self.strings[pointer] 
                for pointer in structure.embedded_strs[offset]
            ]

            # Remove if only one unique string is found
            if len(set(strings)) == 1:
                structure.embedded_strs.pop(offset)
                continue
            
            # Remove if number of unique strings is less then the half of structure embedded strings
            if len(set(strings)) < 0.5 * len(structure.embedded_strs[offset]):
                structure.embedded_strs.pop(offset)
        
        offsets = list(structure.pointed_strs.keys())
        for offset in offsets:
            strings = [
                self.strings[pointer] 
                for pointer in structure.pointed_strs[offset]
            ]

            # Remove if only one unique string is found
            if len(set(strings)) == 1:
                structure.pointed_strs.pop(offset)
                continue
            
            # Remove if number of unique strings is less then the half of structure pointed strings
            if len(set(strings)) < 0.5 * len(structure.pointed_strs[offset]):
                structure.pointed_strs.pop(offset)

        return structure

    def __get_valid_strings_addresses(self, is_insensitive: bool, do_include:bool, strings_to_find:list[str]) -> list[set[int]]:
        # Case insensitive
        if is_insensitive:
            strings_to_find = [string.lower() for string in strings_to_find]
            if do_include:
                valid_strings_addresses = [
                    set([
                        address for address, string in self.strings.items()
                        if string_to_find in string.lower()
                    ]) 
                    for string_to_find in strings_to_find
                ]
            else:
                valid_strings_addresses = [
                    set([
                        address for address, string in self.strings.items() 
                        if string_to_find == string.lower()
                    ]) 
                    for string_to_find in strings_to_find
                ]
            return valid_strings_addresses

        # Case sensitive
        if do_include:
            valid_strings_addresses = [
                set([
                    address for address, string in self.strings.items()
                    if string_to_find in string
                ]) 
                for string_to_find in strings_to_find
            ]
        else:
            valid_strings_addresses = [
                set([
                    address for address, string in self.strings.items() 
                    if string_to_find == string
                ]) 
                for string_to_find in strings_to_find
            ]
        return valid_strings_addresses

    ##############################
    # Main operational functions #
    ##############################
    def _look_into(
        self, 
        valid_strings_addresses:list[set[int]], 
        structure_name:str, 
        into_derived:bool, 
        label:str, 
        referenced_only:bool, 
        table:PrettyTable
        ) -> PrettyTable:
        """ 
        Searches for string addresses into the structure pointers and add the entries into the table.
        Returns the updated table.
        """

        # Impossible
        if into_derived and structure_name == ARRAYS_OF_STRINGS:
            return table

        # Get data
        if into_derived:
            derived_structures:dict[str,list] = self.results[DERIVED_STRUCTURES]
            if not structure_name in derived_structures.keys():
                print(f'No {structure_name} derived structures')
                return table
            data:list = derived_structures[structure_name]
        else:
            data:list = self.results[structure_name] 

        # Special case: arrays of strings
        if structure_name == ARRAYS_OF_STRINGS:
            
            # For each array of strings
            for index, array in enumerate(data):
                found_addresses = []
                assert isinstance(array, PtrsArray)

                # For each valid string address
                for valid_string_address in valid_strings_addresses:
                    
                    # Get the common addresses and add them accordingly
                    addresses_in_common = valid_string_address.intersection(array.strs_array)
                    if not addresses_in_common:
                        break
                    if not referenced_only:
                        found_addresses.extend(addresses_in_common)
                        continue
                    if referenced_only and array.referenced:
                        found_addresses.extend(addresses_in_common)
                
                # Add the found addresses to the table
                for address in found_addresses:
                    table.add_row([
                        label,
                        index,
                        array.referenced,
                        ' ',
                        0,
                        self.strings[address],
                        hex(address)
                    ])
            return table

        # For each structure
        for index, structure in enumerate(data):
            assert isinstance(structure, PointersGroup)

            # For each offset, addresses in embedded strings
            for offset, addresses in structure.embedded_strs.items():
                found_embedded_addresses = []

                # For each valid string address
                for valid_string_address in valid_strings_addresses:
                    
                    # Get the common addresses and add them accordingly
                    addresses_in_common = valid_string_address.intersection(addresses)
                    if not addresses_in_common:
                        break
                    if not referenced_only:
                        found_embedded_addresses.extend(addresses_in_common)
                        continue
                    if referenced_only and structure.referenced and not into_derived:
                        found_embedded_addresses.extend(addresses_in_common)
                
                # Add the found addresses to the table
                for address in found_embedded_addresses:
                    table.add_row([
                        label,
                        index,
                        structure.referenced,
                        'X',
                        offset,
                        self.strings[address],
                        hex(address)
                    ])
            
            # For each offset, addresses in pointed strings
            for offset, addresses in structure.pointed_strs.items():
                found_pointed_addresses = []

                # For each valid string address
                for valid_string_address in valid_strings_addresses:
                    
                    # Get the common addresses and add them accordingly
                    addresses_in_common = valid_string_address.intersection(addresses)
                    if not addresses_in_common:
                        break
                    if not referenced_only:
                        found_pointed_addresses.extend(addresses_in_common)
                        continue
                    if referenced_only and structure.referenced and not into_derived:
                        found_pointed_addresses.extend(addresses_in_common)

                # Add the found addresses to the table
                for address in found_pointed_addresses:
                    table.add_row([
                        label,
                        index,
                        structure.referenced,
                        ' ',
                        offset,
                        self.strings[address],
                        hex(address)
                    ])
                
        return table

    def _expander(
        self, 
        structure_name: str, 
        into_derived: bool, 
        index: int, 
        offset: int, 
        is_pointed: bool, 
        table: PrettyTable
        ) -> PrettyTable:

        # Handling of arrays of strings
        if structure_name == ARRAYS_OF_STRINGS:
            try:
                array = self.results[structure_name][index]
            except:
                print(f'Not enough {structure_name}... Max index {len(self.results[structure_name]) - 1}')
                return table
            assert isinstance(array, PtrsArray)

            for address in array.strs_array:
                table.add_row([
                    f'{hex(address - offset)}',
                    self.strings[address]
                ])
        # Handling of trees without derived structures
        elif structure_name == TREES and not into_derived:
            tree_strings: list[str] = []
            if is_pointed:
                try:
                    tree = self.results[structure_name][index]
                except:
                    print(f'Not enough {structure_name}... Max index {len(self.results[structure_name]) - 1}')
                    return table
                assert(isinstance(tree, Tree))

                for pointer in tree.nodes:
                    if not pointer:
                        tree_strings.append(' ')
                        continue
                    if not pointer + offset in self.pointers.keys():
                        tree_strings.append(' ') 
                        continue
                    if not offset in tree.pointed_strs.keys():
                        tree_strings.append(' ')
                        continue
                    if not self.pointers[pointer + offset] in tree.pointed_strs[offset]:
                        tree_strings.append(' ')
                        continue
                    tree_strings.append(self.strings[self.pointers[pointer + offset]])
                print(buildtree(tree_strings))
            else:
                try:
                    tree_strings = [
                        self.strings[pointer]
                        if pointer else ' '
                        for pointer in 
                        self.results[structure_name][index].get_tree_embedded_strs(offset)
                    ]
                    print(buildtree(tree_strings))
                except:
                    pass
        else:
            if into_derived:
                structures = self.results[DERIVED_STRUCTURES][structure_name]
            else:
                structures = self.results[structure_name]
            structure: PointersGroup = structures[index]
            
            if is_pointed:
                for address in structure.pointed_strs[offset]:
                    if address in self.strings.keys():
                        table.add_row([
                            f'{hex(address - offset)}',
                            self.strings[address]
                        ])
            else:
                for address in structure.embedded_strs[offset]:
                    if address in self.strings.keys():
                        table.add_row([
                            f'{hex(address - offset)}',
                            self.strings[address]
                        ])
        return table

    def _filter_zero(
        self, 
        structure_name: str, 
        into_derived: bool, 
        is_referenced: bool
        ) -> list[PointersGroup]:

        # Get structures list
        structures: list[PointersGroup]
        if into_derived:
            structures = self.results[DERIVED_STRUCTURES][structure_name]
        else:
            structures = self.results[structure_name]

        # Discard the offsets
        structures = [self.__discard_offsets(structure) for structure in structures]

        # Discard structures without strings
        structures = [
            structure for structure in structures 
            if structure.embedded_strs or structure.pointed_strs
        ]

        # Discard structures that have less than 80% of string pointers
        structures = [
            structure for structure in structures 
            if any([
                len(pointers) >= min(0.8 * len(structure), len(structure)-1) 
                for pointers in structure.embedded_strs.values()
            ]) 
            or any([
                len(pointers) >= min(0.8 * len(structure), len(structure)-1) 
                for pointers in structure.pointed_strs.values()
            ])
        ]

        # Filter by referenced
        if is_referenced:
            structures = [structure for structure in structures if structure.referenced]
        
        # Get strings frequencies
        strings_frequencies:dict[str, list[int]] = dict()
        for index, structure in enumerate(structures):
            for strings_pointers in structure.embedded_strs.values():
                for pointer in strings_pointers:
                    string = self.strings[pointer]
                    if not string in strings_frequencies.keys():
                        strings_frequencies[string] = []
                    strings_frequencies[string].append(index)
            for strings_pointers in structure.pointed_strs.values():
                for pointer in strings_pointers:
                    string = self.strings[pointer]
                    if not string in strings_frequencies.keys():
                        strings_frequencies[string] = []
                    strings_frequencies[string].append(index)
        
        def sort_by_strings_mean(structure:PointersGroup) -> float:
            entries = []
            for strings_pointers in structure.embedded_strs.values():
                for pointer in strings_pointers:
                    string = self.strings[pointer]
                    entries.append(len(strings_frequencies[string]))
            for strings_pointers in structure.pointed_strs.values():
                for pointer in strings_pointers:
                    string = self.strings[pointer]
                    entries.append(len(strings_frequencies[string]))
            
            if entries == []:
                return 0
            return mean(entries)
        
        # Sort by the rarity of strings (the rarer, the first)
        structures.sort(key=sort_by_strings_mean)
        return structures

    ########################
    # Operational commands #
    ########################
    @with_argparser(get_finder_parser()) #type:ignore linting error from decorator
    @with_category('Operational commands')
    def do_find_string(self, arguments:argparse.Namespace) -> None:
        """Find structures referring specific strings"""
        
        # Instantiate table data
        table = PrettyTable()
        table.field_names = [
            'Struct type', 
            'Index', 
            'Referenced', 
            'Embedded', 
            'Offset', 
            'String', 
            'String address'
        ]

        # Rename passed arguments with type hinting
        is_insensitive: bool = arguments.insensitive
        do_include: bool = arguments.include
        strings_to_find:list[str] = arguments.string
        search_referenced_strings_only: bool = arguments.referenced
        search_into_derived_structures: bool = arguments.derived_structs
        search_into_cyclics: bool = arguments.circular_double_linked
        search_into_linears: bool = arguments.linear_double_linked
        search_into_trees: bool = arguments.trees
        search_into_linked_lists: bool = arguments.lists
        search_into_arrays_of_strings: bool = arguments.arrays_struct
        search_into_arrays_of_structs: bool = arguments.arrays

        # Get valid strings addresses for strings to search
        valid_strings_addresses = self.__get_valid_strings_addresses(
            is_insensitive,
            do_include,
            strings_to_find
        )

        # Prepare data
        dosearch_name_and_label_structures:list[tuple[bool, str, str]] = [
            (search_into_cyclics,           CIRCULAR_DOUBLY_LINKED_LISTS, 'Circular Double Linked'),
            (search_into_linears,           LINEAR_DOUBLY_LINKED_LISTS,   'Linear Double Linked'),
            (search_into_trees,             TREES,                        'Tree'),
            (search_into_linked_lists,      LINKED_LISTS,                 'Linked List'),
            (search_into_arrays_of_strings, ARRAYS_OF_STRINGS,            'Array of *strings'),
            (search_into_arrays_of_structs, ARRAYS_OF_POINTERS,           'Array of *structs')
        ]

        # Do the researches
        for dosearch, structure_name, structure_label in dosearch_name_and_label_structures:
            if dosearch:
                table = self._look_into(
                    valid_strings_addresses,
                    structure_name,
                    search_into_derived_structures,
                    structure_label,
                    search_referenced_strings_only,
                    table
                )
        
        # Sort and print table and rows number
        table.sortby = 'Referenced'
        table.reversesort = True
        print(f'Results: {len(table._rows)}')
        self.ppaged(table)

    @with_argparser(get_expand_parser()) #type:ignore linting error from decorator
    @with_category("Operational commands")
    def do_expand_struct(self, arguments:argparse.Namespace) -> None:
        """Expand structure at fixed offset"""

        # Prepare table
        table = PrettyTable()
        table.field_names=['Address', 'String']

        # Rename passed arguments with type hinting
        index: int = arguments.index
        offset: int = arguments.offset
        is_pointed: bool = arguments.pointed
        search_into_derived_structures: bool = arguments.derived_structs
        search_into_trees: bool = arguments.trees
        search_into_cyclics: bool = arguments.circular_double_linked
        search_into_linears: bool = arguments.linear_double_linked
        search_into_arrays_of_strings: bool = arguments.arrays
        search_into_arrays_of_structs: bool = arguments.arrays_struct
        search_into_linked_lists: bool = arguments.lists

        # Prepare data
        dosearch_and_name: list[tuple[bool, str]] = [
            (search_into_cyclics,           CIRCULAR_DOUBLY_LINKED_LISTS),
            (search_into_linears,           LINEAR_DOUBLY_LINKED_LISTS),
            (search_into_trees,             TREES),
            (search_into_linked_lists,      LINKED_LISTS),
            (search_into_arrays_of_strings, ARRAYS_OF_STRINGS),
            (search_into_arrays_of_structs, ARRAYS_OF_POINTERS)
        ]

        # Do the expandings
        for dosearch, structure_name in dosearch_and_name:
            if dosearch:
                table = self._expander(
                    structure_name,
                    search_into_derived_structures,
                    index,
                    offset,
                    is_pointed,
                    table
                )

        # Sort and print table
        table.sortby = "Address"
        self.ppaged(table)

    @with_argparser(get_zero_parser())   #type:ignore linting error from decorator
    @with_category("Operational commands")
    def do_zero(self, arguments:argparse.Namespace) -> None:
        """Zero knowledge"""

        # Prepare table
        table = PrettyTable()
        table.field_names = ['Struct type', 'Results']
        table.hrules = ALL

        # Rename arguments and add type hinting
        search_referenced_only: bool = arguments.referenced
        search_into_derived_structures: bool = arguments.derived_structs
        search_into_cyclics: bool = arguments.circular_double_linked
        search_into_linears: bool = arguments.linear_double_linked
        search_into_trees: bool = arguments.trees
        search_into_linked_lists: bool = arguments.lists
        search_into_arrays_of_structs: bool = arguments.arrays_struct

        # Prepare data
        dosearch_name_and_label: list[tuple[bool, str, str]] = [
            (search_into_cyclics,           CIRCULAR_DOUBLY_LINKED_LISTS, 'Circular Double Linked'),
            (search_into_linears,           LINEAR_DOUBLY_LINKED_LISTS,   'Linear Double Linked'),
            (search_into_trees,             TREES,                        'Tree'),
            (search_into_linked_lists,      LINKED_LISTS,                 'Linked List'),
            (search_into_arrays_of_structs, ARRAYS_OF_POINTERS,           'Array of *structs')
        ]

        # Do the zero knowledge research of structures
        resulting_structures: dict[str, list[PointersGroup]] = dict()
        for dosearch, structure_name, label in dosearch_name_and_label:
            if dosearch:
                resulting_structures[label] = self._filter_zero(
                    structure_name,
                    search_into_derived_structures,
                    search_referenced_only
                )
        
        # Prepare results
        for structure_label in resulting_structures.keys():
            for structure in resulting_structures[structure_label]:
                strings = []
                for strings_pointers in structure.embedded_strs.values():
                    strings.extend([
                        self.strings[pointer]
                        for pointer in strings_pointers
                    ])
                for strings_pointers in structure.pointed_strs.values():
                    strings.extend([
                        self.strings[pointer]
                        for pointer in strings_pointers
                    ])
                table.add_row([
                    structure_label,
                    '\n'.join(strings)
                ])

        # Print out
        table.sortby = 'Struct type'
        self.ppaged(table)

if __name__ == '__main__':
    shell = FossilShell(parse_working_directory())
    sys.exit(shell.cmdloop())