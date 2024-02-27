#!/usr/bin/env -S python3 -u
import argparse
import os
import arguments_parsing_common
import subprocess
from constants import (
    POINTERS_FILE
)
from typing import Any

def parse_arguments() -> dict[str, Any]:
    parser = argparse.ArgumentParser(usage='Do a dry run with default values')
    parser.add_argument('elf_dump_file',     type=str, help='The virtual machine ELF dump file.')
    parser.add_argument('working_directory', type=str, help='The working directory in which files will be created and used.')
    parser.add_argument('--ghidra',          type=str, default=os.getenv("GHIDRA_PATH"), help="Path to GHIDRA installation")
    parser.add_argument('--skip',            type=int, help='Skip first n steps (Default: 0)', default=0)
    return arguments_parsing_common._get_dict_arguments(parser)

def check_arguments(arguments:dict[str, Any]) -> dict[str, Any]:
    # Check elf file
    arguments['elf_dump_file'] = os.path.abspath(arguments['elf_dump_file'])
    try:
        _ = open(arguments['elf_dump_file'])
    except Exception as exception:
        print(f'[Error] Something wrong happened while trying to open the elf dump file: {exception}')
        exit(1)
    _.close()

    # Check working directory
    arguments['working_directory'] = os.path.abspath(arguments['working_directory'])

    try:
        os.mkdir(arguments['working_directory'])
    except FileExistsError:
        pass
    except OSError as exception:
        print(f'[Error] Something went wrong with the working directory: {exception}')
        exit(2)

    # Check ghidra path
    if not arguments['ghidra']:
        print(f'[Error] Not a valid ghidra path! ({arguments["ghidra"]}) Exiting...')
        exit(2)
    arguments['ghidra'] = os.path.abspath(arguments['ghidra'])

    # Check skip steps
    if arguments['skip'] < 0 or arguments['skip'] > 4:
        print('Invalid choice of steps to skip. Minimum value == 0, Maximum value == 4. Exiting...')
        exit(3)

    return arguments

if __name__ == '__main__':
    arguments = check_arguments(parse_arguments())
    ############################
    # Step 1: Extract features #
    ############################
    if arguments['skip'] < 1:
        print('[+] Step 1: Extract features...')
        subprocess.check_call([
            'python3',
            'extract_features.py',
            arguments['elf_dump_file'],
            arguments['working_directory'],
            '--ghidra',
            arguments['ghidra']
        ])
        
    #######################################
    # Step 2: Extract doubly linked lists #
    #######################################
    if arguments['skip'] < 2:
        print('[+] Step 2: Extract doubly linked lists...')
        subprocess.check_call([
            'python3',
            'doubly_linked_lists.py',
            os.path.join(arguments['working_directory'], POINTERS_FILE),
            arguments['working_directory'],
        ])

    #########################
    # Step 3: Extract trees #
    #########################
    if arguments['skip'] < 3:
        print('[+] Step 3: Extract trees...')
        subprocess.check_call([
            'python3',
            'trees.py',
            os.path.join(arguments['working_directory'], POINTERS_FILE),
            arguments['working_directory']
        ])

    ##############################
    # Step 4: Extract structures #
    ##############################
    if arguments['skip'] < 4:
        print('[+] Step 4: Extract remaining structures...')
        subprocess.check_call([
            'python3',
            'extract_structs.py',
            arguments['elf_dump_file'],
            arguments['working_directory']
        ])

    ##############################
    # Step 5: Start fossil shell #
    ##############################
    print('[+] Enjoy your shell!')
    subprocess.check_call([
        'python3',
        'fossil.py',
        arguments['working_directory']
    ])