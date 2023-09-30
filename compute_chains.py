import compress_pickle
import os
import script_utils
from chains import ChainGraph, Topology

def parse_arguments() -> dict:
    # Get common parser and add argument
    parser = script_utils.get_parser('directory')
    parser.add_argument('--stats', default=False, action='store_true')
    arguments = script_utils.parse_arguments(parser)

    # Make sure output path exists
    try:
        os.mkdir(arguments['output'])
    except FileExistsError:
        pass
    except FileNotFoundError:
        print('Something went wrong while trying to check the output path! Exiting...')
        exit(1)
    return arguments

def get_most_common(number:int, topology_counters:dict[Topology,int]) -> list[tuple[Topology,int]]:
    sorted_topologies_by_counter = sorted(topology_counters.items(), key=lambda topology: topology[1], reverse=True)
    result = []
    for topology_tuple in sorted_topologies_by_counter:
        if len(result) == number:
            break
        result.append(topology_tuple)
    return result

def print_graph_stats(graph:ChainGraph) -> None:
    # Retrieve topology data and compute overall data
    topology_counters, topology_sizes = graph.topology_counters()
    chains_no = sum(topology_counters.values())
    overall_average_size = sum(size * count for counter in topology_sizes.values() for size, count in counter.items()) / chains_no
    overall_maximum_size = max(map(max, topology_sizes.values()))
    
    # Print overall data
    print(f'\nOffset {graph.offset}') 
    print(f'{graph.num_vertices():,} vertices, {graph.num_edges():,} edges, {chains_no:,} components')
    print(f'Overall average size: {overall_average_size:,.2f}, overall maximum size: {overall_maximum_size:,}')
    
    # Print the 5 most commons data
    others = chains_no
    for topology, counter in get_most_common(5, topology_counters):
        # Calculate for topology data
        counter_size = topology_sizes[topology]
        average_size = sum(size * count for size, count in counter_size.items()) / counter
        maximum_size = max(counter_size)
        others -= counter

        # Print data
        print(f'{topology[0]:,} sources,', end=' ')
        print(f'{topology[1]:,} confluences,', end=' ')
        print(f'{topology[2]:,} sinks: {script_utils.format_percentage(counter/chains_no, True)}', end=' ')
        print(f'average size: {average_size:>5,.2f}, maximum size: {maximum_size:,}')
    print(f'{script_utils.format_percentage(others/chains_no)} others')

if __name__ == '__main__':
    # Parse arguments
    arguments = parse_arguments()

    # Compute statistics
    for graph in arguments['graphs']:
        # For linting purposes
        assert isinstance(graph,ChainGraph)

        # Dump graph
        compress_pickle.dump(graph, os.path.join(arguments['output'], f'{graph.offset}.lz4'))
        
        # Print statistics or offset
        if arguments['stats']:
            print_graph_stats(graph)
        else:
            print(graph.offset, end=' ')