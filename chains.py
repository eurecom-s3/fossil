import collections
import io
import itertools
from collections import Counter, defaultdict
from enum import Enum
from typing import Dict, Iterable, List, Tuple, Union, Hashable

import graph_tool as gt
from graph_tool.topology import label_components
from more_itertools import pairwise
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sortedcontainers import SortedList
import sortednp as snp

POINTER_SIZE = 8  # bytes: 8 => 64 bit, 4 => 32 bit

# we use a signed representation for pointers because of two reasons:
# 1) graph-tool doesn't support unsigned integers: https://git.skewed.de/count0/graph-tool/-/issues/390
# 2) natural to compute differences between pointers when they're signed (by default, subtractions between unsigned
#    integers return floats)
# we map an unsigned pointer to the integer interpretation of the same bits
POINTER_DTYPE_S = 'int64'
POINTER_DTYPE = getattr(np, POINTER_DTYPE_S)  # np.int64 (with POINTER_DTYPE_S == 'int64')
UNSIGNED_POINTER_DTYPE = getattr(np, f'u{POINTER_DTYPE_S}')  # np.uint64
GT_POINTER_DTYPE = f'{POINTER_DTYPE_S}_t'  # 'int64_t' (graph-tool wants this format)

# data structure describing the topology of a component, with number of sources, confluences and sinks
Topology = Tuple[int, int, int]


class ChainShape(Enum):
    """We have two types of chain: lines, with a source and a sink, and a cycle.

    More complex topologies are broken down in several lines and at most one cycle--other topologies are impossible in
    this graph, because out-degree is always at most 1.
    """
    LINE = 1  # one source, one sink
    CYCLE = 2


def roll_cycle(a):
    """Rotate cycles such that they start with the smallest pointer."""

    return np.roll(a, -a.argmin())


def _split_line_chain(constraints, n):
    """Credits to Paolo Ferraris for finding the right algorithm to solve constraints."""
    r2l = {}
    for left, right in constraints:
        if right not in r2l or left > r2l[right]:
            r2l[right] = left
    bottom = 0
    for right, left in sorted(r2l.items()):
        if left >= bottom:
            yield bottom, right
            bottom = left + 1
    yield bottom, n


def _split_cycle_chain(constraints):
    r2l = {}
    l2r = {}
    for left, right in constraints:
        if right not in r2l or left > r2l[right]:
            r2l[right] = left
        if left not in l2r or right > l2r[left]:
            l2r[left] = right
    r2l = sorted(r2l.items())
    bottom = r2l[0][1]
    for right, left in r2l:
        if left >= bottom:
            yield bottom, right
            bottom = left + 1
    for left, right in sorted(l2r.items()):
        if right >= bottom:
            yield bottom, left
            bottom = right + 1


def _sorted_pair(a, b):
    return (a, b) if a <= b else (b, a)


def ptr(p):
    return POINTER_DTYPE(UNSIGNED_POINTER_DTYPE(p))


def ptr_array(pointers):
    return np.fromiter(pointers, UNSIGNED_POINTER_DTYPE).astype(POINTER_DTYPE)


def within_threshold(lst: SortedList, threshold, v):
    index = lst.bisect(v)
    if index > 0 and v - lst[index - 1] < threshold:
        return False
    if index < len(lst) and lst[index] - v < threshold:
        return False
    return True


class PointerSet:

    src: np.ndarray
    dst: np.ndarray

    def __init__(self, pointers: Dict[int, int]):
        src, dst = ptr_array(pointers.keys()), ptr_array(pointers.values())

        # remove self-pointers
        non_self = src != dst
        src, dst = src[non_self], dst[non_self]

        src_sorting = src.argsort()
        self.src, self.dst = src[src_sorting], dst[src_sorting]

    def __len__(self):
        return self.src.size

    def aligned_ratio(self) -> Tuple[float, float]:
        def ar(a): return (a % POINTER_SIZE == 0).sum() / a.size
        return ar(self.src), ar(self.dst)

    def to_dict(self):
        return dict(zip(self.src, self.dst))

    def to_inv_dict(self):
        res = collections.defaultdict(list)
        for s, d in zip(self.src, self.dst):
            res[d].append(s)
        return res


def _dict2tree(root: Hashable, d: Dict[Hashable, List[Hashable]]):
    # equivalent to below, but written in an iterative style to avoid maximum recursion depth
    # return root, [_dict2tree(child, d) for child in d.get(root, [])]
    stack = [root]
    todo = [root]
    node2tree = {}
    while stack:
        neighbors = d.get(stack.pop(), [])
        stack.extend(neighbors)
        todo.extend(neighbors)
    while todo:
        node = todo.pop()
        node2tree[node] = [(child, node2tree.get(child, [])) for child in d.get(node, [])]
    return root, node2tree[root]


def distance_threshold(offset):
    return offset + POINTER_SIZE if offset > 0 else max(-offset, POINTER_SIZE) + 1


class ChainGraph(gt.Graph):

    offset: int
    distance_threshold: int
    component_size: np.ndarray

    def __init__(self, pointer_set: PointerSet, offset: int):
        super().__init__()
        self.offset = offset
        src = pointer_set.src
        dst = pointer_set.dst + offset

        # remove pointers at too short distance:
        # - the struct we're considering must be at least `offset` bytes, and we need to be pointing at another
        #   structure
        # - the pointer is `POINTER_SIZE` bytes, so there must be space for it before we get to this structure
        # - structs of POINTER_SIZE size only would be pointless, as they'd carry no data except the pointers
        # a special case are self-pointers, i.e., pointers to themselves. E.g. Linux uses them in lieu of `NULL`.

        self.distance_threshold = t = distance_threshold(offset)
        in_range = np.abs(dst - src) >= t
        src, dst = src[in_range], dst[in_range]

        # only consider non-isolated pointers
        dst_sorting = np.argsort(dst)
        _, (src_ind, dst_ind) = snp.intersect(src, dst[dst_sorting], indices=True, duplicates=snp.KEEP_MAX_N)
        indices = np.union1d(src_ind, dst_sorting[dst_ind])
        src, dst = src[indices], dst[indices]

        # use LabelEncoder to get consecutive indices for each pointer value
        encoder = LabelEncoder()
        src_ind, dst_ind = encoder.fit_transform(np.concatenate([src, dst])).reshape((2, src.size))
        edges = np.stack([src_ind, dst_ind], axis=1)

        # create the graph and find the connected components
        self.add_edge_list(edges)
        self.vp.ptr = self.new_vertex_property(GT_POINTER_DTYPE, encoder.classes_.astype(POINTER_DTYPE))
        self.vp.component, self.component_size = label_components(self, directed=False)

    def __getstate__(self):
        return super().__getstate__(), self.offset, self.component_size, self.distance_threshold

    def __setstate__(self, state):
        super_state, offset, chain_sizes, threshold = state

        # super().__setstate__(super_state) doesn't work because it calls self.init()
        # https://git.skewed.de/count0/graph-tool/-/issues/696
        gt.Graph.__init__(self)
        blob = super_state["blob"]
        if blob != "":
            sio = io.BytesIO(blob)
            self.load(sio, "gt")

        self.offset, self.component_size, self.distance_threshold = offset, chain_sizes, threshold

    def _incoherences(self, chain: np.ndarray) -> Union[None, List[tuple]]:
        """Check there are no incoherent jumps.

        There should be no intersection for all intervals in range(l, r + POINTER_SIZE)
        where l, r = sorted([*ptr, *ptr + offset])
        """

        threshold = self.distance_threshold
        sorting = np.argsort(chain)
        sorted_pointers = chain[sorting]
        # for each x in incoherent, the item at position sorting[x] is incompatible with that at sorting[x + 1]
        incoherent = np.flatnonzero(np.abs(np.diff(sorted_pointers)) < threshold)
        n = incoherent.size
        if n == 0:
            return None
        res = []
        for a, b in pairwise(itertools.chain([0], np.flatnonzero(np.diff(incoherent) > 1) + 1, [n])):
            # incoherent[a:b] is a group of consecutive values -- here we may have incompatibilities between
            # non-adjacent values in the sorting. For an explanation of the nonzero(diff(...)) trick see
            # https://stackoverflow.com/a/7353335/550097
            if b - a == 1:  # shortcut for the common, easy case of a 1-sized group
                index = incoherent[a]
                res.append(_sorted_pair(sorting[index], sorting[index + 1]))
                continue
            # `group_slice` indexes in `sorting` and `sorted_pointers`. The +2 here looks strange, at least to me:
            # it comes from a first +1 from the definition of `incoherent` (see above) and a second one because range
            # is exclusive on the right
            group_slice = slice(incoherent[a], incoherent[b - 1] + 2)
            pairs = list(zip(sorting[group_slice], sorted_pointers[group_slice]))  # indices & sorted pointers in group
            window = SortedList()  # sliding window containing the positions of pointers
            r = 0  # current right limit of the sliding window
            for l_ind, l_ptr in pairs[:-1]:  # left of the sliding window
                # we grow the sliding window keeping only pointers incompatible with l_ptr
                ptr_threshold = l_ptr + threshold
                for r, (r_ind, r_ptr) in enumerate(pairs[r:], r):
                    if r_ptr >= ptr_threshold:
                        break  # note that, when exiting the loop, r is the current right limit of the sliding window
                    window.add(r_ind)
                else:  # no break
                    r += 1  # make sure the inner loop isn't run anymore
                window_size = len(window)
                assert window_size >= 2, f'{pairs=} {window=} {chain-chain[0]=} {self.offset=}'
                if window_size == 2:
                    res.append(tuple(window))  # only two iterable in the window: just one incompatibility
                else:
                    # for the item at the left of our sliding window, we return incompatibility with the elements at
                    # its left and right, possibly rotating (via modulus) for cyclic chains.
                    # no harm on returning redundant incompatibilities, except for computational load
                    pos = window.index(l_ind)
                    res.append(_sorted_pair(l_ind, window[pos - 1]))  # if pos==0, here -1 does already the work
                    res.append(_sorted_pair(l_ind, window[(pos + 1) % window_size]))  # here no, so we need `%`
                window.remove(l_ind)
        assert len(res) == len(set(res)), res  # we have no duplicates
        return res

    def chain(self, v: int, as_ptr=False) -> Tuple[ChainShape, gt.PropertyArray]:
        """Returns the chain starting at vertex v."""

        ptr_a = self.vp.ptr.a
        if as_ptr:
            v = (ptr_a == v).nonzero()[0][0]
        chain = {v: None}
        n = v
        while neighbors := self.get_out_neighbors(n):
            n = neighbors[0]
            if n in chain:  # cycle
                shape = ChainShape.CYCLE if n == v else ChainShape.LINE
                break
            chain[n] = None
        else:  # no break
            shape = ChainShape.LINE
        chain = ptr_a[list(chain)]
        incoherences = self._incoherences(chain)
        if incoherences is None:
            return shape, chain
        return shape, chain[:min(b for a, b in incoherences)]

    def _chains(self, min_size=3) -> Iterable[Tuple[ChainShape, np.ndarray]]:
        component_size = self.component_size
        component_a = self.vp.component.a
        ptr_a = self.vp.ptr.a
        sources = (self.get_in_degrees(self.get_vertices()) == 0).nonzero()[0]
        not_seen_components = np.ones_like(component_size)

        for n in sources:
            component = component_a[n]
            if component_size[component] < min_size:
                continue
            chain = {}  # we map each node to their position in the chain
            for i in itertools.count():
                chain[n] = i
                # we have two possibilities: the chain ends with either a loop or no outgoing links
                neighbors = self.get_out_neighbors(n)
                if not neighbors:  # no outgoing link: we reached the end of the chain
                    if i + 1 >= min_size:
                        yield ChainShape.LINE, ptr_a[list(chain)]
                    break  # we're done with this I-shaped chain
                assert neighbors.size == 1
                n = neighbors[0]
                if confluence_ind := chain.get(n):
                    # the chain ends with cycle: this is a P-shaped pattern we decompose in line and cycle
                    chain = list(chain)
                    if confluence_ind >= min_size:
                        yield ChainShape.LINE, ptr_a[chain[:confluence_ind]]
                    if not_seen_components[component] and i + 1 - confluence_ind >= min_size:
                        yield ChainShape.CYCLE, roll_cycle(ptr_a[chain[confluence_ind:]])
                    break  # we're done with this P-shaped chain
            not_seen_components[component] = False
        # rings are in components with no sources, so we've still not seen them
        for component in not_seen_components.nonzero()[0]:
            size = component_size[component]
            if size < min_size:
                continue
            n = np.flatnonzero(component_a == component)[0]
            chain = [n]
            for _ in range(int(size) - 1):  # we need to cast to int because uint - int returns a float
                n = self.get_out_neighbors(n)[0]
                chain.append(n)
            yield ChainShape.CYCLE, roll_cycle(ptr_a[chain])

    def chains(self, min_size: int = 3, only_lines=False) -> Iterable[Tuple[ChainShape, np.ndarray]]:
        """Return an iterable over all chains of length at least `min_len` with their ChainShape.

        Rings are returned with the smallest pointer first.
        """

        seen_heads = set()
        for pair in self._chains(min_size):
            shape, chain = pair
            constraints = self._incoherences(chain)
            if constraints is None:
                yield pair
                continue
            n = chain.size
            if shape == ChainShape.LINE:
                slices = _split_line_chain(constraints, n)
            else:
                if only_lines:
                    continue
                slices = _split_cycle_chain(constraints)
            for a, b in slices:
                head = chain[a]
                if head in seen_heads:
                    continue
                seen_heads.add(head)
                if a < b:
                    if b - a >= min_size:
                        yield ChainShape.LINE, chain[a:b]
                else:
                    if n - a + b >= min_size:
                        yield ChainShape.LINE, np.concatenate([chain[a:], chain[:b]])

    def component_view(self, label: int) -> gt.GraphView:
        """Return the graph view for a given component."""

        return gt.GraphView(self, vfilt=self.vp.component.a == label)

    def _parent_tree(self, sink):
        ptr_vp = self.vp.ptr
        ptr_a = ptr_vp.a
        threshold = self.distance_threshold

        sink_ptr = ptr_a[sink]
        chain = [sink_ptr]
        sorted_chain = SortedList(chain)
        sink_parents = [(parent, parent_ptr)
                        for parent, parent_ptr in self.get_in_neighbors(sink, [ptr_vp])
                        if abs(parent_ptr - sink_ptr) >= threshold]
        parents = {sink_ptr: [parent_ptr for _, parent_ptr in sink_parents]}
        stack = [(sink_ptr, *parent_pair) for parent_pair in sink_parents]
        while stack:
            # noinspection PyTupleAssignmentBalance
            child_ptr, parent, parent_ptr = stack.pop()
            while child_ptr != chain[-1]:
                sorted_chain.remove(chain.pop())
            chain.append(parent_ptr)
            sorted_chain.add(parent_ptr)
            grandpas = []
            for grandpa_pair in self.get_in_neighbors(parent, [ptr_vp]):
                grandpa_ptr = grandpa_pair[1]
                if within_threshold(sorted_chain, threshold, grandpa_ptr):
                    grandpas.append(grandpa_pair)
            if grandpas:
                stack.extend((parent_ptr, *grandpa_pair) for grandpa_pair in grandpas)
                parents[parent_ptr] = [grandpa_ptr for _, grandpa_ptr in grandpas]
        return sink_ptr, parents

    def component_breakdowns(self, min_size=3):
        threshold = self.distance_threshold
        ptr_vp = self.vp.ptr
        ptr_a = ptr_vp.a

        component2vertices = defaultdict(list)
        for i, c in enumerate(self.vp.component.a):
            component2vertices[c].append(i)

        for component in np.flatnonzero(self.component_size >= min_size):
            vertices = component2vertices[component]
            sinks = [vertices[i] for i in np.flatnonzero(self.get_out_degrees(vertices) == 0)]
            assert len(sinks) <= 1

            cycle = None
            if len(sinks) == 0:  # no sinks: the component ends with a cycle
                n = vertices[0]  # we start from an arbitrary element of the component and look for a loop
                chain = {n: 0}
                for i in itertools.count(1):
                    n, = self.get_out_neighbors(n)
                    if n in chain:
                        confluence_index = chain[n]
                        break
                    chain[n] = i
                else:  # no break: impossible
                    raise RuntimeError("Bug: this point should never be reached")
                chain = list(chain)[confluence_index:]
                assert np.array_equal(self.get_out_neighbors(chain[-1]), [chain[0]])
                size = len(chain)
                if size >= min_size:
                    pointers = ptr_a[chain]
                    if np.min(np.diff(np.sort(pointers))) >= threshold:
                        cycle = roll_cycle(pointers)
                for a, b in pairwise(chain + chain[:1]):  # we consider every entry point to the cycle as a sink itself
                    sinks.extend(x for x in self.get_out_neighbors(a) if x != b)

            assert cycle is None or cycle.size >= min_size
            yield cycle, map(self._parent_tree, sinks)

    def topology(self, label: int) -> Tuple[Topology, int]:
        chain = self.component_view(label)
        vertices = chain.get_vertices()
        in_degrees = chain.get_in_degrees(vertices)
        sources = sum(in_degrees == 0)
        confluences = sum(in_degrees > 1)
        sinks = sum(chain.get_out_degrees(vertices) == 0)
        size = vertices.size
        assert in_degrees.max() <= vertices.size
        assert confluences < sources
        assert sinks <= 1
        return (sources, confluences, sinks), size

    def topology_counters(self) -> Tuple[Dict[Topology, int], Dict[Topology, Dict[int, int]]]:
        counter = Counter()
        sizes = defaultdict(Counter)
        for label in (self.component_size > 2).nonzero()[0]:
            topology, size = self.topology(label)
            counter[topology] += 1
            sizes[topology][size] += 1
        return counter, sizes
