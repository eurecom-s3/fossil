import graph_tool as gt
import io
import itertools
import numpy as np
import sortednp as snp
from enum import Enum
from graph_tool.topology import label_components
from more_itertools import pairwise
from numpy._typing import NDArray
from sklearn.preprocessing import LabelEncoder
from sortedcontainers import SortedList
from typing import Iterable, Iterator, Tuple



# we use a signed representation for pointers because of two reasons:
# 1) graph-tool doesn't support unsigned integers: https://git.skewed.de/count0/graph-tool/-/issues/390
# 2) natural to compute differences between pointers when they're signed (by default, subtractions between unsigned
#    integers return floats)
# we map an unsigned pointer to the integer interpretation of the same bits
POINTER_SIZE = 8  # bytes: 8 => 64 bit, 4 => 32 bit
GT_POINTER_DTYPE = 'int64_t'  # 'int64_t' (graph-tool wants this format)

# data structure describing the topology of a component, with number of sources, confluences and sinks
Topology = Tuple[int, int, int]


class ChainShape(Enum):
    """
    We have two types of chain: lines, with a source and a sink, and a cycle.

    More complex topologies are broken down in several lines and at most one cycle--other topologies are impossible in
    this graph, because out-degree is always at most 1.
    """
    LINE = 1  # one source, one sink
    CYCLE = 2

class PointerSet:

    src_pointers: NDArray[np.int64]
    dst_pointers: NDArray[np.int64]

    def __init__(self, pointers: dict[int, int]) -> None:
        src_pointers = np.fromiter(list(pointers.keys()),   np.uint64).astype(np.int64)
        dst_pointers = np.fromiter(list(pointers.values()), np.uint64).astype(np.int64)

        # remove self-pointers
        non_self = src_pointers != dst_pointers
        src_pointers, dst_pointers = src_pointers[non_self], dst_pointers[non_self]

        src_sorting = src_pointers.argsort()
        self.src_pointers, self.dst_pointers = src_pointers[src_sorting], dst_pointers[src_sorting]

    def __len__(self) -> int:
        return self.src_pointers.size

    def aligned_ratio(self) -> tuple[float, float]:
        ar = lambda a: (a % POINTER_SIZE == 0).sum() / a.size
        return float(ar(self.src_pointers)), float(ar(self.dst_pointers))

    def to_dict(self) -> dict[np.int64, np.int64]:
        return dict(zip(self.src_pointers, self.dst_pointers))

    def to_inv_dict(self) -> dict[np.int64, list[np.int64]]:
        res:dict[np.int64, list[np.int64]] = dict()
        for source, destination in zip(self.src_pointers, self.dst_pointers):
            if not destination in res.keys():
                res[destination] = []
            res[destination].append(source)
        return res

class ChainGraph(gt.Graph):

    offset: np.int64
    distance_threshold: np.int64
    component_size: NDArray[np.int64]
    vertex_properties: gt.PropertyDict

    def __init__(self, pointer_set: PointerSet, offset: np.int64) -> None:
        super().__init__()
        self.offset = offset
        src_pointers:NDArray[np.int64] = pointer_set.src_pointers
        dst_pointers:NDArray[np.int64] = pointer_set.dst_pointers + offset

        # remove pointers at too short distance:
        # - the struct we're considering must be at least `offset` bytes, and we need to be pointing at another
        #   structure
        # - the pointer is `POINTER_SIZE` bytes, so there must be space for it before we get to this structure
        # - structs of POINTER_SIZE size only would be pointless, as they'd carry no data except the pointers
        # a special case are self-pointers, i.e., pointers to themselves. E.g. Linux uses them in lieu of `NULL`.

        self.distance_threshold = self._get_distance_threshold(offset)
        in_range = (np.abs(dst_pointers - src_pointers) >= self.distance_threshold)
        src_pointers, dst_pointers = src_pointers[in_range], dst_pointers[in_range]

        # only consider non-isolated pointers
        dst_sorting = np.argsort(dst_pointers)
        _, (src_index, dst_index) = snp.intersect(
            src_pointers, 
            dst_pointers[dst_sorting], 
            indices=True, 
            duplicates=snp.KEEP_MAX_N
        )
        indices = np.union1d(src_index, dst_sorting[dst_index])
        src_pointers, dst_pointers = src_pointers[indices], dst_pointers[indices]

        # use LabelEncoder to get consecutive indices for each pointer value
        encoder = LabelEncoder()
        indices = encoder.fit_transform(np.concatenate([src_pointers, dst_pointers]))
        assert isinstance(indices, np.ndarray)
        src_index, dst_index = indices.reshape((2, src_pointers.size))
        edges = np.array(np.stack([src_index, dst_index], axis=1),np.int64)

        # create the graph and find the connected components
        self.add_edge_list(edges)
        self.vertex_properties.pointers = self.new_vertex_property(
            GT_POINTER_DTYPE,
            np.array(encoder.classes_, np.int64)
        )
        components = label_components(self, directed=False)
        assert len(components) == 2
        assert isinstance(components[1], np.ndarray)
        components = (components[0], np.array(components[1], np.int64))
        self.vertex_properties.component, self.component_size = components

    def __getstate__(self) -> tuple[dict, np.int64, NDArray[np.int64], np.int64]:
        return super().__getstate__(), self.offset, self.component_size, self.distance_threshold

    def __setstate__(self, state:tuple[dict, np.int64, NDArray[np.int64], np.int64]) -> None:
        super_state, offset, chain_sizes, threshold = state

        # super().__setstate__(super_state) doesn't work because it calls self.init()
        # https://git.skewed.de/count0/graph-tool/-/issues/696
        gt.Graph.__init__(self)
        blob = super_state['blob']
        if blob != '':
            sio = io.BytesIO(blob)
            self.load(sio, 'gt')

        self.offset, self.component_size, self.distance_threshold = offset, chain_sizes, threshold

    def _get_distance_threshold(self, offset:np.int64) -> np.int64:
        if offset > 0:
            return offset + POINTER_SIZE
        return np.max([-offset, np.int64(POINTER_SIZE)]) + 1

    def _is_within_threshold(self, sorted_list:SortedList, vertex:np.int64) -> bool:
        index = int(sorted_list.bisect(vertex))
        last = sorted_list[index-1]
        assert not isinstance(last, list)
        last = np.int64(last)
        
        if index > 0 and vertex - last < self.distance_threshold:
            return False

        if index < len(sorted_list):
            element = sorted_list[index]
            assert not isinstance(element, list)
            element = np.int64(element)
            if element - vertex < self.distance_threshold:
                return False
        return True

    def _roll_cycle(self, cycle:NDArray[np.int64]) -> NDArray[np.int64]:
        return np.roll(cycle, -cycle.argmin())

    def _parent_tree(self, sink: int) -> tuple[int, dict[int, list[np.int64]]]:
        """
        Returns the sink pointer and the parents dictionary
        """
        pointers_property = self.vertex_properties.pointers
        assert isinstance(pointers_property, gt.VertexPropertyMap)

        property_array = pointers_property.get_array()
        assert isinstance(property_array, gt.PropertyArray)
        
        pointers_array:NDArray[np.int64] = np.array(property_array, np.int64)
        sink_pointer:int = pointers_array[sink]
        chain:list[np.int64] = [np.int64(sink_pointer)]
        sorted_chain = SortedList(chain) # SortedList[np.int64]

        vertex_neighbors = self.get_in_neighbors(sink, [pointers_property])
        assert isinstance(vertex_neighbors, np.ndarray) # 2 Dimensions
        neighbors: NDArray[np.int64] = np.array(vertex_neighbors, np.int64)

        sink_parents:list[tuple[np.int64, np.int64]] = [
            (parent, parent_pointer)
            for parent, parent_pointer in neighbors
            if abs(parent_pointer - np.int64(sink_pointer)) >= self.distance_threshold
        ]
        parents:dict[int, list[np.int64]] = {
            sink_pointer: [parent_pointer for _, parent_pointer in sink_parents]
        }
        stack:list[tuple[np.int64, np.int64, np.int64]] = [
            (np.int64(sink_pointer), *parent_pair) 
            for parent_pair in sink_parents
        ]
        while stack:
            child_pointer, parent, parent_pointer = stack.pop()
            while child_pointer != chain[-1]:
                sorted_chain.remove(chain.pop())
            
            chain.append(parent_pointer)
            sorted_chain.add(parent_pointer)
            grandparents:list[tuple[np.int64, np.int64]] = []

            grandparents_pairs = self.get_in_neighbors(parent, [pointers_property])
            assert isinstance(grandparents_pairs, np.ndarray) # 2 Dimensions

            for grandpa_pair in np.array(grandparents_pairs, np.int64):
                grandpa_pair: NDArray[np.int64]
                grandpa_pointer:np.int64 = grandpa_pair[1]
                
                if self._is_within_threshold(sorted_chain, grandpa_pointer):
                    to_add:tuple[np.int64, ...] = tuple(grandpa_pair)
                    assert len(to_add) == 2
                    grandparents.append(to_add)
                
            if grandparents:
                stack.extend(
                    (parent_pointer, *grandpa_pair) 
                    for grandpa_pair in grandparents
                )
                parents[int(parent_pointer)] = [grandpa_pointer for _, grandpa_pointer in grandparents]
        return sink_pointer, parents

    def component_breakdowns(self, min_size:int = 3) -> Iterator[tuple[NDArray[np.int64]|None, Iterable[tuple[int, dict[int, list[np.int64]]]]]]:
        pointers_property = self.vertex_properties.pointers
        assert isinstance(pointers_property, gt.VertexPropertyMap)

        property_array = pointers_property.get_array()
        assert isinstance(property_array, gt.PropertyArray)
        property_array = np.array(property_array, np.int64)

        component_to_vertices:dict[int, list[int]] = dict()
        components_property = self.vertex_properties.component
        assert isinstance(components_property, gt.VertexPropertyMap)

        components_array = components_property.get_array()
        assert isinstance(components_array, gt.PropertyArray)

        for index, component in enumerate(components_array):
            if component not in component_to_vertices.keys():
                component_to_vertices[component] = []
            component_to_vertices[component].append(index)

        for component in np.flatnonzero(self.component_size >= min_size):
            vertices = component_to_vertices[component]
            sinks:list[int] = [
                vertices[index] 
                for index in np.flatnonzero(self.get_out_degrees(vertices) == 0)
            ]
            assert len(sinks) <= 1
            cycle = None

            if len(sinks) == 0:  # no sinks: the component ends with a cycle
                element = vertices[0]  # we start from an arbitrary element of the component and look for a loop
                chain = {element: 0}
                
                for index in itertools.count(1):
                    neighbors = self.get_out_neighbors(element)
                    assert isinstance(neighbors, np.ndarray)
                    element:int = neighbors[0]
                    if element in chain:
                        confluence_index = chain[element]
                        break
                    chain[element] = index
                else:  # no break: impossible
                    raise RuntimeError("Bug: this point should never be reached")
                
                chain = list(chain)[confluence_index:]
                neighbors = self.get_out_neighbors(chain[-1])
                assert isinstance(neighbors, np.ndarray)
                assert np.array_equal(neighbors, np.array([chain[0]]))

                size = len(chain)
                if size >= min_size:
                    pointers = property_array[chain]
                    assert isinstance(pointers, np.ndarray)
                    pointers = np.array(pointers, np.int64)
                    if np.min(np.diff(np.sort(pointers))) >= self.distance_threshold:
                        cycle = self._roll_cycle(pointers)
                    
                for a, b in pairwise(chain + chain[:1]):  # we consider every entry point to the cycle as a sink itself
                    neighbors = self.get_out_neighbors(a)
                    assert isinstance(neighbors, np.ndarray)
                    neighbors = np.array(neighbors, np.int64)
                    sinks.extend(int(neighbor) for neighbor in neighbors if int(neighbor) != b)

            assert cycle is None or cycle.size >= min_size
            yield cycle, map(self._parent_tree, sinks)