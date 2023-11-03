#!/usr/bin/env -S python3 -u

import argparse
import ctypes
import functools
import json
import logging
import os
import subprocess

from address_translators import get_virtual_space
from address_translators import (
    RISCVSV32, 
    RISCVSV39, 
    AArch64Long, 
    ARMShort, 
    IntelAMD64, 
    IntelIA32, 
    IntelPAE
)
from compress_pickle import dump
from constants import (
    VIRTUALS_TO_OFFSETS_FILE,
    OFFSETS_TO_VIRTUALS_FILE,
    POINTERS_FILE,
    INVERSE_POINTERS_FILE,
    STRINGS_FILE,
    BITMAP_FILE,
    EXTERNAL_REFERENCES_FILE,
    FUNCTIONS_FILE
)
from memory_objects import ELFDump
from pathlib import Path
from uuid import uuid4

data_keys = [
    'elf_dump', 'output_path', 'ignore_page',
    'debug', 'ghidra_path'
]

def parse_arguments() -> dict:
    parser = argparse.ArgumentParser()
    parser.add_argument('elf_dump', help='Memory dump in ELF format. Check `qemu_elf_dumper.py`', type=str)
    parser.add_argument('output_path', help='Output path for the files', type=str)
    parser.add_argument('--ignore_page', help="Physical page to be ignored during the virtual-to-physical mapping. In order to select more pages just repeat the `--ignore-page page_no` flag", action='append', type=functools.partial(int, base=0), default=[])
    parser.add_argument('--debug', help="Enable debug print data", default=False, action="store_true")
    parser.add_argument('--ghidra', help="Path to GHIDRA installation", type=str, default=os.getenv("GHIDRA_PATH"))
    args = parser.parse_args()

    return {
        'elf_dump': args.elf_dump,
        'output_path': args.output_path,
        'ignore_page': args.ignore_page,
        'debug': args.debug,
        'ghidra_path': args.ghidra
    }

def check_arguments(args:dict) -> None:
    # Check input elf dump
    try:
        elf_dump = open(args['elf_dump'])
        elf_dump.close()
    except Exception as exception:
        print(f'[Error] Something bad happened when trying to open the dump file!\nException details: {exception}\nExiting...')
        exit(1)

    # Check ghidra path
    if args['ghidra_path'] is None:
        print('Please use --ghidra option or set GHIDRA_PATH environment variable')
        exit(2)

    # Set debug if selected
    if args['debug']:
        logging.basicConfig(level=logging.DEBUG)

    # Check output path
    if not Path(args['output_path']).exists():
        print('[Error] Destination path does not exist! Exiting...')
        exit(3)

def load_main_data(elf_dump:str, ignored_pages:list[int], output_path:str) -> tuple[str,AArch64Long|ARMShort|RISCVSV32|RISCVSV39|IntelAMD64|IntelIA32|IntelPAE]:
    """ 
    Loads the ELF dump, retrieves memory data and exports the kernel virtual address space.
    Returns the architecture and the virtual space object
    """
    
    # Load the ELF file and parse it
    print('Load ELF...')
    elf_object = ELFDump(elf_dump)

    # Retrieve architecture
    machine_data = elf_object.get_machine_data()
    if not 'Architecture' in machine_data.keys():
        print('[Error] Something is wrong in the ELF dump! The `Architecture` key in the machine data is missing. Exiting...')
        exit(4)
    architecture = machine_data['Architecture']
    print(f'Architecture: {architecture}')
    
    # Get the virtual space and retrieve the following:
    # - Pointers
    # - Reverse pointers
    # - Strings
    # - Memory bitmap
    print('Get virtual space...')
    virtual_space = get_virtual_space(elf_object, ignored_pages)
    virtual_space.retrieve_pointers()
    virtual_space.retrieve_strings()
    virtual_space.create_bitmap()

    # Export virtual memory
    print('Export kernel Virtual Address Space as ELF...')
    virtual_space.export_virtual_memory_elf(os.path.join(output_path, 'extracted_kernel.elf'))

    return architecture, virtual_space

def get_processor(architecture:str, wordsize:int) -> str:
    """ 
    Only x86 and aarch64 are supported!
    """
    if 'x86' in architecture or '386' in architecture:
        return f'x86:LE:{wordsize*8}:default -cspec gcc'
    return f'AARCH64:LE:{wordsize*8}:v8A -cspec default'

def compute_static_analysis(virtual_space:AArch64Long|ARMShort|RISCVSV32|RISCVSV39|IntelAMD64|IntelIA32|IntelPAE, architecture:str, ghidra_path:str, output_path:str) -> str:
    """ 
    Computes the static analysis with Ghidra.
    Returns the output filename
    """
    print('Start static analysis...')

    # Define working data
    output_filename = os.path.join(output_path,'ghidra.json')
    processor = get_processor(architecture.lower(), virtual_space.wordsize)
    ghidra_command = os.path.join(ghidra_path, 'support/analyzeHeadless') \
        + f' /tmp/ ghidra_project_{uuid4()}' \
        + f' -import {os.path.join(output_path, "extracted_kernel.elf")}' \
        + f' -processor {processor}' \
        + f' -scriptPath {os.path.join(os.path.dirname(__file__),"ghidra")} -postScript export_xrefs.py {output_filename}'

    # Call ghidra script
    try:
        subprocess.check_output(ghidra_command.split())
    except subprocess.CalledProcessError as exception:
        print(f'[Error] Something went wrong in executing ghidra!\nException details: {exception}\nExiting...')
        exit(5)

    print('Static analysis ended succesfully!')
    
    return output_filename

def filter_analyzed_data(path_to_results:str, virtual_space:AArch64Long|ARMShort|RISCVSV32|RISCVSV39|IntelAMD64|IntelIA32|IntelPAE) -> tuple[set, set]:
    """ 
    Filters results from ghidra static analysis.
    Returns external_references and functions
    """
    external_references_data = set()
    functions = set()

    # Check on virtual space
    if virtual_space.virtual_to_offset is None:
        print('[Error] Something is wrong about virtual space! Exiting...')
        exit(5)

    # Get raw data
    with open(path_to_results) as output:
        (external_references_data, functions) = json.load(output)

    # Select the conversion function
    conversion_function = lambda x: ctypes.c_uint32(x).value
    if virtual_space.wordsize == 8:
        conversion_function = lambda x: ctypes.c_uint64(x).value
    
    # Get the data
    external_references_data = set(
        [
            conversion_function(x) 
            for x in external_references_data.values()
            if virtual_space.virtual_to_offset[conversion_function(x)] != -1
        ]
    )
    functions = set(
        [
            conversion_function(x)
            for x in functions.values()
            if virtual_space.virtual_to_offset[conversion_function(x)] != -1
        ]
    )

    if len(functions) == 0:
        print('[Warning] No functions identified...')

    return external_references_data, functions

def dump_data(output_path:str, external_references:set, functions:set, virtual_space:AArch64Long|ARMShort|RISCVSV32|RISCVSV39|IntelAMD64|IntelIA32|IntelPAE) -> None:
    print('Saving features...')
    dump(virtual_space.virtual_to_offset,     os.path.join(output_path, VIRTUALS_TO_OFFSETS_FILE))
    dump(virtual_space.offset_to_virtual,     os.path.join(output_path, OFFSETS_TO_VIRTUALS_FILE))
    dump(virtual_space.pointers,              os.path.join(output_path, POINTERS_FILE))
    dump(virtual_space.reverse_pointers,      os.path.join(output_path, INVERSE_POINTERS_FILE))
    dump(virtual_space.strings,               os.path.join(output_path, STRINGS_FILE))
    dump(virtual_space.memory_bitmap,         os.path.join(output_path, BITMAP_FILE))
    dump(external_references,                 os.path.join(output_path, EXTERNAL_REFERENCES_FILE))
    dump(functions,                           os.path.join(output_path, FUNCTIONS_FILE))

if __name__ == '__main__':
    # Arguments parsing and checking
    arguments = parse_arguments()
    check_arguments(arguments)
    assert list(arguments.keys()) == data_keys

    # Get architecture and virtual space
    architecture, virtual_space = load_main_data(
        arguments['elf_dump'], 
        arguments['ignore_page'],
        arguments['output_path']
    )

    # Compute static analysis
    results_filename = compute_static_analysis(
        virtual_space,
        architecture,
        arguments['ghidra_path'],
        arguments['output_path']
    )

    # Get external references and functions
    external_references, functions = filter_analyzed_data(results_filename, virtual_space)    

    # Save data structures
    dump_data(
        arguments['output_path'],
        external_references,
        functions,
        virtual_space
    )
