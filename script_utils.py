import argparse
import compress_pickle
import dask.bag as db
import logging
import numpy as np
import os

from chains import PointerSet, ChainGraph
from dask.bag import Bag
from dask.diagnostics import ProgressBar

DEFAULT_TASKS_PER_PROCESSOR = 4

# +------------------------------+
# | Common usage "public" funcs  |
# +------------------------------+
def format_percentage(ratio:float, fixed_width:bool=False) -> str:
    format_string = '{:.2f}%'
    if fixed_width:
        format_string = '{:>5.2f}%'
    return format_string.format(100 * ratio)

# +------------------------------+
# | Arguments parsing utilities  |
# +------------------------------+
def _get_output_help(output_type:str) -> str:
    if output_type == 'directory':
        return 'destination path for output file(s)'
    if output_type == 'pickle':
        return 'pickled file in which to store the result; will be compressed according to extension (e.g. lzma, lz4, ...)'
    return ''

def _get_arguments_dests(parser:argparse.ArgumentParser) -> list[str]:
    # Blacklist of unwanted arguments
    blacklist = ['help']

    # Collect argument destinations
    argument_dests = []
    for action in parser._get_positional_actions():
        argument_dests.append(action.dest)
    for action in parser._get_optional_actions():
        argument_dests.append(action.dest)

    # Filter out blacklisted arguments
    for unwanted in blacklist:
        if unwanted in argument_dests:
            argument_dests.remove(unwanted)

    return argument_dests

def _get_dict_arguments(parser:argparse.ArgumentParser) -> dict:
    arguments = parser.parse_args()
    attributes = _get_arguments_dests(parser)
    arguments_dict = {}
    for attribute in attributes:
        arguments_dict[attribute] = arguments.__getattribute__(attribute)
    return arguments_dict

# +---------------------------------------------+
# | Common actions based on submitted arguments |
# +---------------------------------------------+
def _setup_logging(is_silent:bool) -> None:
    logging_level = logging.INFO
    if is_silent:
        logging_level = logging.WARNING
    logging.basicConfig(format='{levelname} {asctime} {message}', style='{', level=logging_level)
    logging.info('starting')
    if not is_silent:
        ProgressBar().register()

def _compute_pointer_set(pointers_file:str) -> PointerSet:
    pointer_set = PointerSet(compress_pickle.load(pointers_file))
    aligned_src, aligned_dest = pointer_set.aligned_ratio()
    sources_percent = format_percentage(aligned_src)
    destinations_percent = format_percentage(aligned_dest)
    logging.info(f'{len(pointer_set):,} pointers [{sources_percent} sources and {destinations_percent} destinations aligned]')
    return pointer_set

def _compute_chain_graphs(min_offset:int, max_offset:int, offset_step:int, pointers:PointerSet) -> Bag:
    offsets = np.arange(min_offset, max_offset + 1, offset_step)
    return db.from_sequence(offsets, partition_size=1) \
        .map(lambda offset: ChainGraph(pointers, offset))

def get_parser(output_type:str='directory') -> argparse.ArgumentParser:
    """ 
    Creates an ArgumentParser object and returns it.
    The arguments are as follows:

    +-----------------------+
    | Positional arguments  |
    +-----------------------+
    [+] 'pointers'      : pickle file containing pointers; can be a compressed file
    [+] 'output'        : file or directory for output
    
    +-----------------------+
    | Optional arguments    |
    +-----------------------+
    [+] '--min-offset'  : minimum bytes offset to take into account     (default -64)
    [+] '--max-offset'  : maximum bytes offset to take into account     (default  64)
    [+] '--offset-step' : distance in bytes between consecutive offsets (default 8)
    [+] '--silent'      : silence the console output                    (default False)
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('pointers',         help="pickle file containing pointers; can be a compressed file")
    parser.add_argument('output',           help=_get_output_help(output_type))
    parser.add_argument('--min-offset',     type=int, default=-64,  help="minimum offset to take into account, in bytes (default -64)")
    parser.add_argument('--max-offset',     type=int, default=64,   help="maximum offset to take into account, in bytes (default 64)")
    parser.add_argument('--offset-step',    type=int, default=8,    help="distance between consecutive offsets, in bytes (default 8)")
    parser.add_argument('--silent',         action='store_true',    help="avoid console output")
    return parser

def parse_arguments(parser:argparse.ArgumentParser) -> dict:
    """ 
    Parse the arguments from the given parser.
    Returns parsed arguments in a dict.
    Default returned data:
    - pointers:     chains.PointerSet
    - output:       str
    - graphs:       dask.bag.Bag[list[ChainGraph]]
    - silent:       bool
    - min_offset:   int
    - max_offset:   int
    - offset_step:  int
    """
    
    arguments = _get_dict_arguments(parser)
    _setup_logging(arguments['silent'])
    arguments['pointers'] = _compute_pointer_set(arguments['pointers'])
    arguments['graphs'] = _compute_chain_graphs(
        arguments['min_offset'],
        arguments['max_offset'],
        arguments['offset_step'],
        arguments['pointers']
    )
    return arguments


def default_npartitions():
    return DEFAULT_TASKS_PER_PROCESSOR * len(os.sched_getaffinity(0))
