import argparse
from collections import namedtuple
from multiprocessing import Pool
import os
import os.path
import sys

from compress_pickle import load, dump

from chains import PointerSet, ChainGraph

# global variables we set in main()
args: argparse.Namespace
pointer_set: PointerSet


Stats = namedtuple('Stats', 'offset num_vertices num_edges topology_counters topology_sizes')


def fmt_percentage(ratio, fixed_width=False):
    fmt = '{:>5.2f}%' if fixed_width else '{:.2f}%'
    return fmt.format(100 * ratio)


def compute_chain_graph(offset):
    g = ChainGraph(pointer_set, offset)
    dump(g, os.path.join(args.dest, f'{offset}.lz4'))
    if args.stats:
        counter, sizes = g.topology_counters()
        return Stats(offset, g.num_vertices(), g.num_edges(), counter, sizes)
    else:
        return offset


def print_graph_stats(stats):
    print()
    print(f"Offset {stats.offset}")
    n_chains = sum(stats.topology_counters.values())
    print(f"{stats.num_vertices:,} vertices, {stats.num_edges:,} edges, {n_chains:,} components")
    avg_size = sum(size * count for ctr in stats.topology_sizes.values() for size, count in ctr.items()) / n_chains
    max_size = max(map(max, stats.topology_sizes.values()))
    print(f"Overall avg size: {avg_size:,.2f}, max: {max_size:,}")
    others = n_chains
    for t, count in stats.topology_counters.most_common(5):
        others -= count
        print(f"{t[0]:,} sources, {t[1]:,} confluences, {t[2]:,} sinks:",
              fmt_percentage(count / n_chains, True), end=' ')
        size_ctr = stats.topology_sizes[t]
        avg_size = sum(size * count for size, count in size_ctr.items()) / count
        max_size = max(size_ctr)
        print(f"avg size: {avg_size:>5,.2f}, max: {max_size:,}")
    print(fmt_percentage(others / n_chains), "others")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ptrs', help='Pickle file containing pointers; can be compressed')
    parser.add_argument('dest', help='Gzipped shelve file in which to store the output')
    parser.add_argument('--stats', default=False, action='store_true')
    parser.add_argument('--min_offset', type=int, default=-64)
    parser.add_argument('--max_offset', type=int, default=64)
    parser.add_argument('--offset_step', type=int, default=8)
    args = parser.parse_args()

    pointer_set = PointerSet(load(args.ptrs))
    aligned_src, aligned_dst = pointer_set.aligned_ratio()

    print(f"{len(pointer_set):,} pointers [{fmt_percentage(aligned_src)} sources "
          f"and {fmt_percentage(aligned_dst)} destinations aligned]")

    os.mkdir(args.dest)
    offsets = range(args.min_offset, args.max_offset + 1, args.offset_step)
    with Pool() as p:
        if args.stats:
            for s in p.imap(compute_chain_graph, offsets):
                print_graph_stats(s)
        else:
            print()
            for offset in p.imap_unordered(compute_chain_graph, offsets):
                print(offset, end=' ')
                sys.stdout.flush()
