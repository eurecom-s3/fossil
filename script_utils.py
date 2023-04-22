import argparse
import logging
import os

import compress_pickle
import dask.bag as db
from dask.diagnostics import ProgressBar
import numpy as np

from chains import PointerSet, ChainGraph

DEFAULT_TASKS_PER_PROCESSOR = 4


def setup_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('pointers', help="pickle file containing pointers; can be a compressed file")
    parser.add_argument('--min_offset', type=int, default=-64,
                        help="minimum offset to take into account, in bytes (default -64)")
    parser.add_argument('--max_offset', type=int, default=64,
                        help="maximum offset to take into account, in bytes (default 64)")
    parser.add_argument('--offset_step', type=int, default=8,
                        help="distance between consecutive offsets, in bytes (default 8)")
    parser.add_argument('--silent', action='store_true', help="avoid console output")
    parser.add_argument('output',
                        help='pickled file in which to store the result; will be compressed according to extension')
    return parser


def setup_logging(args):
    # the `style` argument is missing from the signature
    # noinspection PyArgumentList
    logging.basicConfig(format="{levelname} {asctime} {message}", style='{',
                        level=logging.WARNING if args.silent else logging.INFO)
    logging.info("starting")
    if not args.silent:
        ProgressBar().register()


def fmt_percentage(ratio, fixed_width=False):
    fmt = '{:>5.2f}%' if fixed_width else '{:.2f}%'
    return fmt.format(100 * ratio)


def compute_pointer_set(args):
    pointer_set = PointerSet(compress_pickle.load(args.pointers))
    aligned_src, aligned_dst = pointer_set.aligned_ratio()
    logging.info(f"{len(pointer_set):,} pointers [{fmt_percentage(aligned_src)} sources "
                 f"and {fmt_percentage(aligned_dst)} destinations aligned]")
    return pointer_set


def offsets(args):
    return np.arange(args.min_offset, args.max_offset + 1, args.offset_step)


def compute_chain_graphs(args, pointer_set):
    graphs = db.from_sequence(offsets(args), partition_size=1).map(lambda offset: ChainGraph(pointer_set, offset))
    return graphs


def default_npartitions():
    return DEFAULT_TASKS_PER_PROCESSOR * len(os.sched_getaffinity(0))
