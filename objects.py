import numpy as np
from statistics import mode
from collections import Counter, defaultdict
from bisect import bisect_left, bisect_right
import ctypes
from struct import unpack
import time
import ipaddress

from addrspaces import IMOffsets
from bitarray import bitarray

class MemoryObject:
    @classmethod
    def prepare(
        cls, 
        pointers: dict[int,int], 
        pointer_size: int, 
        virtual_to_offset: IMOffsets, 
        bitmap: bitarray, 
        strings: dict[int,str], 
        external_references: set[int], 
        functions: set[int], 
        elf_dump_file: str
        ) -> None:

        # Define object pointers
        cls.pointers = pointers
        cls.sorted_pointers = sorted(pointers.keys())
        cls.pointers_set = set(cls.sorted_pointers)
        
        # Define object autopointers
        cls.sorted_autopointers = sorted((pointer for pointer,pointed in cls.pointers.items() if pointer == pointed))
        cls.autopointers_set = set(cls.sorted_autopointers)

        # Define object strings
        cls.strings = strings
        cls.sorted_strings = sorted(strings.keys())
        cls.strings_set = set(strings.keys())

        # Define obejct pointer size, virtual to offset and bitmap
        cls.pointer_size = pointer_size
        cls.virtual_to_offset = virtual_to_offset
        cls.bitmap = bitmap

        # Define typings and conversions based on pointer size
        if pointer_size == 4:
            cls.uint_conversion_function = lambda self, x: ctypes.c_uint32(x).value
            cls.dtype = np.uint32
        else:
            cls.uint_conversion_function = lambda self, x: ctypes.c_uint64(x).value
            cls.dtype = np.uint64

        # Define external references
        cls.external_references = external_references
        cls.referenced_external_references = set()

        # Define input dump file and functions
        cls.elf_dump_file = open(elf_dump_file, "rb")
        cls.functions = functions

    @classmethod
    def is_pointer_null(cls, pointer:int) -> bool:
        elf_offset = cls.virtual_to_offset[pointer]
        if elf_offset == -1:
            return False
        if cls.bitmap[elf_offset : elf_offset + cls.pointer_size].any():
            return False
        return True

class PointersGroup(MemoryObject):
    def __init__(self, ptrs_list, offsets=tuple()):
        self.ptrs_list:list[int] = ptrs_list              # List of structural pointer (main ones)
        self.mode_distance = 0                  # Most common distance among structural pointers (upper limit to structure size)
        self.structural_offsets = set([0])         # Offsets at which can be found structural pointers
        self.dests_offsets:tuple[np.int64,np.int64] = offsets            # Offsets to be used to reconstruct the topology starting from the structural pointers
        
        self.autostructural_offsets = []        # Offsets of pointers pointing to the head of the structure itself
        self.shape = (-1, -1)                   # Tuple containing the assumed limits of the structs and threshold limit
        
        self.near_ptrs:dict = {}                     # dict offset:(set pointers) with at least threshold pointers
        self.near_ptrs_threshold = 0

        self.valid_near_offsets = set()         # Contains only offset which are not autostructural ones nor structural in the shape range
        
        self.pointed_strs = defaultdict(list)   # Contains for each offset the list of addresses of string pointers
        self.embedded_strs = defaultdict(list)  # Contains for each offset the list of addresses of strings embedded 

        self.extimation_type = ""               # Describe how the structure shape is determined   
        
        self.struct_type = -1                   # Index describing the struct

        xrefs = self.external_references.intersection(self.ptrs_list)
        self.referenced_external_references.update(xrefs)
        self.referenced = bool(xrefs)
        self.abs_timestamps = {}
        self.rel_timestamps = {}
        self.ip_addresses = {}
        self.list_child_offsets = {}            # Offset of probable children lists
        self.function_ptrs_offset = {}          # Offset of function pointers
        self.referenced_fn = bool(self.functions.intersection(self.ptrs_list))

        # self.strs_offsets = None     # dict offset:(set pointers to strs) with at least threshold pointers
        # self.strs = None             # dict offset:string with at least threshold occupation

    def __len__(self):
        return len(self.ptrs_list)

    def get_u64(self, offset):
        self.elf_dump_file.seek(offset, 0)
        try:
            return unpack("<Q", self.elf_dump_file.read(8))[0]
        except:
            return None

    def get_u32(self, offset):
        self.elf_dump_file.seek(offset, 0)
        try:
            return unpack("<I", self.elf_dump_file.read(4))[0]
        except:
            return None

    def find_timestamps(self, min_time, max_time=time.time_ns()):

        abs_timestamps = defaultdict(list)
        rel_timestamps = defaultdict(list)

        for offset in range(self.shape[0], self.shape[0] + self.shape[1]):
            for ptr in self.ptrs_list:
                file_offset = self.virtual_to_offset[ptr + offset]
                if file_offset == -1:
                    continue
                
                candidate = self.get_u64(file_offset)
                if candidate is None:
                    continue

                if min_time < candidate < max_time:
                    abs_timestamps[offset].append(candidate)

                if min_time + candidate < max_time:
                    rel_timestamps[offset].append(candidate)
            
            # Ignore all equal timestamps!
            if len(set(abs_timestamps[offset])) == 1:
                abs_timestamps.pop(offset)
            if len(set(rel_timestamps[offset])) == 1:
                rel_timestamps.pop(offset)
        
        self.abs_timestamps = abs_timestamps
        self.rel_timestamps = rel_timestamps

    def find_ips(self):
        ips = {}
        candidates = []
        for offset in range(self.shape[0], self.shape[0] + self.shape[1]):
            if offset in self.near_ptrs:
                continue
            
            localhost_found = False
            candidates.clear()
            for ptr in self.ptrs_list:
                file_offset = self.virtual_to_offset[ptr + offset]
                if file_offset == -1:
                    continue
                
                candidate = self.get_u32(file_offset)
                if candidate is None:
                    continue
                
                if candidate == 0x7F000001: # Localhost 127.0.0.1
                    localhost_found = True
                candidates.append(candidate)

            if not localhost_found:
                continue

            ips[offset] = [ipaddress.IPv4Address(x) for x in candidates]
            
        self.ip_addresses = ips

    def estimate_latest_ptrs(self, max_offset, threshold = 0.9):
        positive_offsets = []
        negative_offsets = []
        l_ptrs = len(self.ptrs_list)
        m_so = min(self.structural_offsets)
        M_so = max(self.structural_offsets)
        for offset, (_, zeros) in self.near_ptrs.items():
            if m_so <= offset <= M_so:
                continue 
            true_ptrs_ratio = (l_ptrs - zeros)/l_ptrs
            if offset > 0:
                positive_offsets.append((offset, true_ptrs_ratio))
            else:
                negative_offsets.append((offset, true_ptrs_ratio))

        if positive_offsets:
            latest_positive = positive_offsets[-1][0]
            for offset, value in positive_offsets[::-1]:
                if value > threshold:
                    latest_positive = offset
                    break
        else:
            latest_positive = max_offset 
        
        if negative_offsets:
            latest_negative = negative_offsets[0][0]
            for offset, value in negative_offsets:
                if value > threshold:
                    latest_negative = offset
                    break
        else:
            latest_negative = -max_offset

        return latest_negative, latest_positive

    def determine_shape(self, max_offset: int=8192, near_threshold: float=0.9, autostruct_threshold: float=0.9, align_threshold: float=0.5, fake=False):
        self.find_near_pointers(max_offset, near_threshold)  # A this point the structure is stimated to have a maximum size of mode_distance but we don't know anything about the alignment (we have a window of [-mode, mode] bytes)
        
        if fake:
            self.shape = (-max_offset//2, max_offset//2)
            self.extimation_type = "fake"
        
        else:
            l_n, l_p = self.estimate_latest_ptrs(max_offset)
            # Check if there are structural pointers pointing to the head of the
            # structure, in that case we can recover exactly where the structure
            # start and a maxium size (the mode distance)
            possible_start, autostructural_offsets = self.identify_struct_start(max_offset, autostruct_threshold)
            if autostructural_offsets:
                self.autostructural_offsets = autostructural_offsets
                # self.shape = (possible_start, self.mode_distance)
                self.shape = (possible_start, min(self.mode_distance, abs(possible_start) + l_p))
                self.extimation_type = "autostructural"
            else:
                self.shape = (l_n, min(self.mode_distance, abs(l_n) + l_p))
                self.extimation_type = "latest pointers"

            # else:
            #     # If there are no structural pointers pointing to the head of the
            #     # structure try to determine a valid alignment for the structure 
            #     start, _ = self.estimate_align(align_threshold)
            #     if start == -1:
            #         self.shape = (-1, -1)
            #         self.extimation_type = "failed"
            #         self.valid_near_offsets = set()
            #         return
            #     else:
            #         self.shape = (start, self.mode_distance)
            #         self.extimation_type = "align"

        self.valid_near_offsets = {x for x in set(self.near_ptrs.keys()).difference(self.autostructural_offsets).difference(self.structural_offsets) if self.shape[0] <= x < self.shape[0] + self.shape[1]}
        
        self.list_child_offsets = {offset for offset in self.valid_near_offsets if 0 < len(self.near_ptrs[offset][0].intersection(self.autopointers_set)) < len(self.near_ptrs[offset][0]) }
        self.list_child_offsets.difference_update(self.dests_offsets)
        self.list_child_offsets.difference_update(self.autostructural_offsets)

        self.function_ptrs_offset = {offset for offset in self.valid_near_offsets if self.near_ptrs[offset][0].intersection(self.functions)}

    def find_near_pointers(self, max_offset: int=8192, threshold: float=0.9):
        """
        Considering all the pointers in base_ptrs as pointers contained in the same
        type of structure, it returns a dictionary with the offsets and all
        the pointers contained in at least threshold structures at a -max_offset <
        distance < max_offset from the base pointers and the commond distance among
        base pointers
        """
        base_ptrs = sorted(self.ptrs_list)
        len_base_ptrs = len(base_ptrs)
        len_dump_ptrs = len(self.pointers)

        visited_ptrs = defaultdict(list)

        mode_distance = min(max_offset, int(mode( np.diff( np.array(base_ptrs, dtype=np.uint64) ) ) )) # The most common distance among base pointers
        
        # Find all the offsets containing pointers near to the base pointer
        min_idx = 0
        for base_ptr in base_ptrs:
            
            min_idx = bisect_right(self.sorted_pointers, base_ptr - mode_distance, lo=min_idx)
            
            for idx in range(min_idx, len_dump_ptrs):
                diff = self.sorted_pointers[idx] - base_ptr

                if diff >= mode_distance:
                    break
                
                visited_ptrs[diff].append(self.sorted_pointers[idx])

        # Add locations point to NULL
        nulls = defaultdict(int)
        for offset in visited_ptrs.keys():
            for base_ptr in base_ptrs:
                
                ptr = base_ptr + offset
                if ptr in self.pointers_set or \
                (elf_offset := self.virtual_to_offset[ptr]) == -1 or \
                self.bitmap[elf_offset:elf_offset+self.pointer_size].any():
                    continue
                
                nulls[offset] += 1

        # Consider only offsets containing at least threshold% of pointers and NULLs
        real_threshold = min(len_base_ptrs - 1, threshold * len_base_ptrs)
        near_ptrs = {offset:(set(ptrs), nulls[offset]) for offset, ptrs in visited_ptrs.items() if len(ptrs) + nulls.get(offset, 0) >= real_threshold}

        self.near_ptrs = near_ptrs
        self.mode_distance = mode_distance
        self.near_ptrs_threshold = threshold

    def identify_struct_start(self, max_offset=8192, threshold=0.9):
        """
        Identify possible exact start of the structure using pointers which point to
        the start of other structure of the same topology (example struct
        task_struct *parent pointer in Linux task_struct). Return possible struct
        start and pointers offsets with share the same difference between associated
        pointers and base_ptrs
        """
        base_ptrs_array = np.array(self.ptrs_list, dtype=np.uint64)
        offset_min_distance = {}
        distances = defaultdict(int)

        for offset, (ptrs_s, _) in self.near_ptrs.items():
            
            # Ignore structural offsets, these offsets return always a distance of 0
            # from the start base pointers
            if offset in self.structural_offsets:
                continue

            # Find all the destination of pointers (excluding auto pointers) at a fixed offset, if those
            # pointers point to the starts of same type structures of the structure
            # under analysis there will be an common offset (at least in threshold%
            # of the cases)
            dests = [self.pointers[x] for x in ptrs_s if x not in self.autopointers_set]
            if not dests: # Ignore offsets containing only autopointers
                continue
            minimum_distances = [self.uint_conversion_function( np.min(base_ptrs_array - x) ) for x in dests] # Collect for each pointer the minimum distance between its destination and all the base pointers
            if not minimum_distances:
                continue
            common_distance = Counter(minimum_distances).most_common(1)[0]
            distance, count = common_distance
            if count < min(threshold * len(ptrs_s), len(ptrs_s) - 1) or \
                distance >= max_offset or -distance > offset or not (-distance <= offset <= -distance + self.mode_distance - self.pointer_size): # Ignore too big distances
                continue

            offset_min_distance[offset] = distance
            distances[distance] += count
        
        # Consider all the offset at the same time, the common distance among them
        # could be the structure start referring to base ptrs offset
        if offset_min_distance:
            possible_start = sorted(distances.items(), key=lambda x: (x[1], x[0]))[-1][0]
            near_ptrs_same_type = [k for k,v in offset_min_distance.items() if v == possible_start]
        else:
            return -max_offset, []

        # Check if te structure starting at possible_start contains all the
        # structural offsets
        possible_start = -possible_start
        if possible_start > 0 or  not (possible_start  <= min(self.structural_offsets) <= max(self.structural_offsets) <= possible_start + self.mode_distance - self.pointer_size) or \
           any([not (possible_start  <= x <= possible_start + self.mode_distance - self.pointer_size) for x in near_ptrs_same_type]):
            return possible_start, []
        
        near_ptrs_same_type.sort()
        return possible_start, near_ptrs_same_type

    def estimate_align(self, threshold=0.5):
        """
        Estimate the alignment of the structure inside the window, returns valid offsets
        """
        valid_ptrs_per_window = []
        offsets = sorted([k for k,t in self.near_ptrs.items() \
            if (abs(k-max(self.structural_offsets) - self.pointer_size) <= self.mode_distance and \
               abs(k-min(self.structural_offsets)) <= self.mode_distance and \
               1 - t[1]/len(t[0]) > min(threshold, 1 - 1/len(t[0]))) or k in self.structural_offsets]) # Consider only offsets with at least threshold% of not null pointers
        ptrs_len = [len(self.near_ptrs[x][0]) for x in offsets]
        
        idx_final = bisect_left(offsets, min(self.structural_offsets) + 1)
                
        for idx in range(0, idx_final):
            total = 0
            offsets_counter = 0
            limit = offsets[idx] + self.mode_distance - self.pointer_size
            for idx2 in range(idx, idx_final):
                if offsets[idx2] > limit:
                    break
                total += ptrs_len[idx2]
                offsets_counter += 1
            try:
                valid_ptrs_per_window.append(total/offsets_counter)
            except:
                valid_ptrs_per_window.append(0)
        
        if not valid_ptrs_per_window:
            return -1, -1

        start_idx = valid_ptrs_per_window.index(max(valid_ptrs_per_window))
        
        return offsets[start_idx], self.mode_distance


    def find_strings(self, threshold=0.9):
        """
        Find pointed and embedded strings
        """
        len_base_ptrs = len(self.ptrs_list)
        len_strs = len(self.strings)

        embded_strs = defaultdict(list)
        pointed_strs = defaultdict(list)

        for elem in self.ptrs_list:

            # Find pointed strings
            for offset in self.valid_near_offsets:
                            
                addr = elem + offset
                if addr in self.autopointers_set:
                    continue

                try:
                    pointed_addr = self.pointers[addr]
                    if pointed_addr in self.strings:
                        pointed_strs[offset].append(pointed_addr)
                except KeyError:
                    pass
            
            # Find embedded strings
            minimum_address = elem + self.shape[0]
            min_idx = bisect_right(self.sorted_strings, minimum_address)
        
            for idx in range(min_idx, len_strs):
                diff = self.sorted_strings[idx] - elem

                if diff >= self.shape[0] + self.shape[1]:
                    break
                
                embded_strs[diff].append(self.sorted_strings[idx])


        real_threshold = min(len_base_ptrs - 1, threshold * len_base_ptrs)
        for offset, collected_strs in pointed_strs.items():
            if len(collected_strs) >=  min(len(self.near_ptrs[offset]) - 1, threshold * len(self.near_ptrs[offset])) and len(collected_strs) > 2:
                self.pointed_strs[offset] = collected_strs

        # real_threshold = min(len_base_ptrs - 1, threshold * len_base_ptrs)
        for diff, collected_strs in embded_strs.items():
            if len(collected_strs) >= real_threshold and len(collected_strs) > 2:
                self.embedded_strs[diff] = collected_strs
            
    def find_similar_string(self, string):
        """
        Look if a similar string is pointed or embedded in the data structure
        """
        results = {}
        string = string.lower()
        for offset, s_addresses in self.embedded_strs.items():
            for s_address in s_addresses:
                if string in (r := self.strings[s_address]):
                    results[(offset, False)] = r

        for offset, s_addresses in self.pointed_strs.items():
            for s_address in s_addresses:
                if string in (r := self.strings[s_address]):
                    results[(offset, True)] = r

        return tuple(results)

    def extract_strings(self, offset, is_pointed):
        if is_pointed:
            return [self.strings[x] for x in self.pointed_strs[offset]]
        else:
            return [self.strings[x] for x in self.embedded_strs[offset]]

class LinkedList(PointersGroup):
    def __init__(self, base_ptrs, offsets, is_ciclic):
        super().__init__(base_ptrs, offsets)

        self.is_terminated = self.termination_status()
        self.is_ciclic = is_ciclic

    def termination_status(self):
        """
        Return True if the list is terminated (NULL or autoptrs ending), False (data ending) otherwise
        """
        if self.ptrs_list[-1] in self.autopointers_set:
            return True

        try:
            deref = self.pointers[self.ptrs_list[-1]] + self.dests_offsets
            if deref  == self.ptrs_list[-1]:
                return True

            elf_off = self.virtual_to_offset[deref]
            if elf_off == -1 or self.bitmap[elf_off:elf_off + self.pointer_size].any():
                return False
        except:
            pass

        elf_off = self.virtual_to_offset[self.ptrs_list[-1]]
        if elf_off == -1 or self.bitmap[elf_off:elf_off + self.pointer_size].any():
            return False
        else:
            return True
        
class DoubleLinkedList(PointersGroup):
     def __init__(self, base_ptrs:list[int], base_ptrs2:list[int], offsets, is_ciclic):
        
        s_distance:int = base_ptrs[0] - base_ptrs2[-1]

        if s_distance < 0:
            super().__init__(base_ptrs, offsets)
            self.ptrs_list_back:list[int] = base_ptrs2
        else:
            super().__init__(base_ptrs2, offsets[::-1])
            self.ptrs_list_back:list[int] = base_ptrs


        self.structural_offsets = set((0, abs(s_distance))) # Offsets of next and prev pointers
        dest_offsets = abs( abs(int(offsets[0])) - abs(int(offsets[1])) )

        # Heuristics: there are D bytes bewtween next and prev pointers of an
        # element of the double linked list, I suppose that *next + offset_next
        # and *prev + offset_prev so offset_prev - offest_next = D1 == D  (with
        # some absolute values...) We are considering degenerate, for example, structures in
        # which next point to next pointer in next structure and prev point to
        # the head of previous structure (not to previous prev)
        #
        # Example of degenerate case
        # -----<--     -----           -----       =
        # |   |   |    |   |           |   |         |
        # |   |   |    |   |           |   |         |  D1
        # | p |    ----| p |           | p | =       |
        # |   |        |   |           |   |  | D    |
        # | n |        | n |---------->| n | =     =
        # -----        -----           -----
        #           D != D1
        self.is_degenerate = abs(s_distance) != dest_offsets
        self.is_ciclic = is_ciclic

class Tree(PointersGroup):
    def __init__(self, base_ptrs, offsets, levels):
        self.nodes = base_ptrs
        base_ptrs = [x for x in base_ptrs if x]
        super().__init__(base_ptrs, offsets)
        self.levels = levels

    def get_tree_embedded_strs(self, offset):
        tree_list = []
        for ptr in self.nodes:
            if ptr and ptr + offset in self.embedded_strs[offset]:
                tree_list.append(ptr + offset)
            else:
                tree_list.append(None)
        return tree_list

    def get_tree_pointed_strs(self, offset):
        tree_list = []
        for ptr in self.nodes:
            try:
                if ptr and self.pointers[ptr + offset] in self.pointed_strs[offset]:
                    tree_list.append(self.pointers[ptr + offset])
                else:
                    tree_list.append(None)
            except Exception as e:
                print(e)
                tree_list.append(None)
        return tree_list


class PtrsArray(MemoryObject):
    def __init__(self, ptrs_list):
        self.ptrs_list = ptrs_list       # Array of pointers
        dest_ptrs = {self.pointers[x] for x in ptrs_list}
        self.referenced = bool(self.external_references.intersection(self.ptrs_list))
        self.structs = None
        self.referenced_fn = bool(self.functions.intersection(self.ptrs_list))

        # Find if all the pointers point directly to strings
        if dest_ptrs.issubset(self.strings_set):
            self.strs_array = list(dest_ptrs)

        else:
            self.strs_array = []
            if len(dest_ptrs) > 2:
                self.structs = PointersGroup(list(dest_ptrs))     # Struct pointed by pointers
                # Threat as an struct Test *array[XX] (array of pointer to structs)
                self.structs.determine_shape()
                if self.structs.shape != (-1, -1):
                    self.structs.find_strings() # <= the strings at offset 0 corresponds to char **array[XX] (array of double pointers to char) or an array of pointer to structs with field 0 as char *
                    self.structs.find_ips()
