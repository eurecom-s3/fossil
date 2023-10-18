import ctypes
import ipaddress
import numpy as np

from addrspaces import IMOffsets
from bisect import bisect_left, bisect_right
from bitarray import bitarray
from collections import Counter
from io import BufferedReader
from statistics import mode
from struct import unpack
from typing import Callable

class MemoryObject:

    # Attributes type hinting
    pointers: dict[int,int]
    sorted_pointers: list[int]
    pointers_set: set[int]
    sorted_autopointers: list[int]
    autopointers_set: set[int]
    strings: dict[int,str]
    sorted_strings: list[int]
    strings_set: set[int]
    pointer_size: int
    virtual_to_offset: IMOffsets
    bitmap: bitarray
    uint_conversion_function: Callable[[int], int]
    dtype: type
    external_references: set[int]
    referenced_external_references: set[int]
    elf_dump_file: BufferedReader
    functions: set[int]

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
            cls.uint_conversion_function = lambda x: ctypes.c_uint32(x).value
            cls.dtype = np.uint32
        else:
            cls.uint_conversion_function = lambda x: ctypes.c_uint64(x).value
            cls.dtype = np.uint64

        # Define external references
        cls.external_references = external_references
        cls.referenced_external_references: set[int] = set()

        # Define input dump file and functions
        cls.elf_dump_file = open(elf_dump_file, 'rb')
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
    
    # Attributes type hinting
    pointers_list: list[int]
    mode_distance: int
    structural_offsets: set[int]
    destination_offsets: tuple[int, ...]
    autostructural_offsets: list[int]
    shape: tuple[int, int]
    near_pointers: dict[int, tuple[set[int], int]]
    near_pointers_threshold: float
    valid_near_offsets: set[int]
    pointed_strings: dict[int, list[int]]
    embedded_strings: dict[int, list[int]]
    extimation_type: str
    structure_type: int
    external_references: set[int]
    referenced_external_references: set[int]
    referenced: bool
    ip_addresses: dict[int, list[ipaddress.IPv4Address]]
    children_lists_offset: set[int]
    function_pointers_offset: set[int]
    referenced_functions: bool

    def __init__(self, pointers_list:list[int], offsets: tuple[int, ...] = tuple()) -> None:
        self.pointers_list = pointers_list      # List of structural pointer (main ones)
        self.mode_distance = 0                  # Most common distance among structural pointers (upper limit to structure size)
        self.structural_offsets = set([0])      # Offsets at which can be found structural pointers
        self.destination_offsets = offsets      # Offsets to be used to reconstruct the topology starting from the structural pointers
        self.autostructural_offsets = []        # Offsets of pointers pointing to the head of the structure itself
        self.shape = (-1, -1)                   # Tuple containing the assumed limits of the structs and threshold limit
        self.near_pointers = {}                 # dict offset:(set pointers) with at least threshold pointers
        self.near_pointers_threshold = 0
        self.valid_near_offsets = set()         # Contains only offset which are not autostructural ones nor structural in the shape range
        self.pointed_strings = dict()           # Contains for each offset the list of addresses of string pointers
        self.embedded_strings = dict()          # Contains for each offset the list of addresses of strings embedded 
        self.extimation_type = ''               # Describe how the structure shape is determined   
        self.structure_type = -1                # Index describing the struct
        external_references = self.external_references.intersection(self.pointers_list)
        self.external_references: set[int]
        self.referenced_external_references.update(external_references)
        self.referenced = bool(external_references)
        self.ip_addresses = {}
        self.children_lists_offset = set()      # Offset of probable children lists
        self.function_pointers_offset = set()   # Offset of function pointers
        self.referenced_functions = bool(self.functions.intersection(self.pointers_list))

    def __len__(self) -> int:
        return len(self.pointers_list)

    def get_from_file_as_uint32(self, offset: int) -> int|None:
        self.elf_dump_file.seek(offset, 0)
        try:
            return unpack("<I", self.elf_dump_file.read(4))[0]
        except:
            return None

    def find_ip_addresses(self) -> None:
        ip_addresses: dict[int, list[ipaddress.IPv4Address]] = {}
        candidates = []
        for offset in range(self.shape[0], self.shape[0] + self.shape[1]):
            if offset in self.near_pointers:
                continue
            
            localhost_found = False
            candidates.clear()
            for pointer in self.pointers_list:
                file_offset = self.virtual_to_offset[pointer + offset]
                if file_offset == -1:
                    continue
                
                candidate = self.get_from_file_as_uint32(file_offset)
                if candidate is None:
                    continue
                
                if candidate == 0x7F000001: # Localhost 127.0.0.1
                    localhost_found = True
                candidates.append(candidate)

            if not localhost_found:
                continue

            ip_addresses[offset] = [
                ipaddress.IPv4Address(candidate) 
                for candidate in candidates
            ]
            
        self.ip_addresses = ip_addresses

    def estimate_latest_pointers(self, max_offset:int, threshold:float = 0.9) -> tuple[int, int]:
        positive_offsets:list[tuple[int,float]] = []
        negative_offsets:list[tuple[int,float]] = []
        pointers_list_length = len(self.pointers_list)
        minimum_structural_offset = min(self.structural_offsets)
        maximum_structural_offset = max(self.structural_offsets)
        
        for offset, (_, zeros) in self.near_pointers.items():
            if minimum_structural_offset <= offset <= maximum_structural_offset:
                continue 
            pointers_ratio = (pointers_list_length - zeros)/pointers_list_length
            if offset > 0:
                positive_offsets.append((offset, pointers_ratio))
            else:
                negative_offsets.append((offset, pointers_ratio))

        if positive_offsets:
            latest_positive_offset = positive_offsets[-1][0]
            for offset, value in positive_offsets[::-1]:
                if value > threshold:
                    latest_positive_offset = offset
                    break
        else:
            latest_positive_offset = max_offset 
        
        if negative_offsets:
            latest_negative_offset = negative_offsets[0][0]
            for offset, value in negative_offsets:
                if value > threshold:
                    latest_negative_offset = offset
                    break
        else:
            latest_negative_offset = -max_offset

        return latest_negative_offset, latest_positive_offset

    def determine_shape(
        self, 
        max_offset:int = 8192, 
        near_pointers_threshold:float = 0.9, 
        autostructural_pointers_threshold:float = 0.9, 
        fake=False
        ) -> None:
        self.find_near_pointers(max_offset, near_pointers_threshold)  # A this point the structure is expected to have a maximum size of mode_distance but we don't know anything about the alignment (we have a window of [-mode, mode] bytes)
        
        if fake:
            self.shape = (-max_offset//2, max_offset//2)
            self.extimation_type = 'fake'
        else:
            latest_negative_offset, latest_positive_offset = self.estimate_latest_pointers(max_offset)
            # Check if there are structural pointers pointing to the head of the
            # structure, in that case we can recover exactly where the structure
            # start and a maxium size (the mode distance)
            possible_start, autostructural_offsets = self.identify_structure_start(max_offset, autostructural_pointers_threshold)
            if autostructural_offsets:
                self.autostructural_offsets = autostructural_offsets
                self.shape = (
                    possible_start, 
                    min(
                        self.mode_distance, 
                        abs(possible_start) + latest_positive_offset
                    )
                )
                self.extimation_type = 'autostructural'
            else:
                self.shape = (
                    latest_negative_offset, 
                    min(
                        self.mode_distance, 
                        abs(latest_negative_offset) + latest_positive_offset
                    )
                )
                self.extimation_type = 'latest pointers'

        self.valid_near_offsets = {
            offset for offset in 
            set(self.near_pointers.keys())\
            .difference(self.autostructural_offsets)\
            .difference(self.structural_offsets) 
            if self.shape[0] <= offset < self.shape[0] + self.shape[1]
        }
        
        self.children_lists_offset = {
            offset for offset in self.valid_near_offsets 
            if 0 < len(self.near_pointers[offset][0].intersection(self.autopointers_set)) < len(self.near_pointers[offset][0]) 
        }

        self.children_lists_offset.difference_update(self.destination_offsets)
        self.children_lists_offset.difference_update(self.autostructural_offsets)

        self.function_pointers_offset = {
            offset for offset in self.valid_near_offsets 
            if self.near_pointers[offset][0].intersection(self.functions)
        }

    def find_near_pointers(self, max_offset:int = 8192, threshold:float = 0.9) -> None:
        """
        Considering all the pointers in base pointers as pointers contained in the same
        type of structure, it returns a dictionary with the offsets and all
        the pointers contained in at least threshold structures at a -max_offset <
        distance < max_offset from the base pointers and the commond distance among
        base pointers
        """
        base_pointers = sorted(self.pointers_list)
        base_pointers_length = len(base_pointers)
        dumped_pointers_length = len(self.pointers)
        visited_pointers:dict[int, list[int]] = {}

        # The most common distance among base pointers
        common_distance = min(
            max_offset, 
            int(mode(
                np.diff(np.array(base_pointers,dtype=np.uint64))
            ))
        )
        
        # Find all the offsets containing pointers near to the base pointer
        minimum_index = 0
        for base_pointer in base_pointers:
            minimum_index = bisect_right(
                self.sorted_pointers, 
                base_pointer - common_distance, 
                lo=minimum_index
            )
            for index in range(minimum_index, dumped_pointers_length):
                distance = self.sorted_pointers[index] - base_pointer
                if distance >= common_distance:
                    break
                if distance not in visited_pointers.keys():
                    visited_pointers[distance] = []
                visited_pointers[distance].append(self.sorted_pointers[index])

        # Add locations point to NULL
        null_pointers_number_by_offset: dict[int, int] = {}
        for offset in visited_pointers.keys():
            for base_pointer in base_pointers:
                pointer = base_pointer + offset
                elf_offset = self.virtual_to_offset[pointer]

                if pointer in self.pointers_set:
                    continue
                if elf_offset == -1:
                    continue
                if self.bitmap[elf_offset : elf_offset + self.pointer_size].any():
                    continue
                if not offset in null_pointers_number_by_offset.keys():
                    null_pointers_number_by_offset[offset] = 0

                null_pointers_number_by_offset[offset] += 1

        # Consider only offsets containing at least threshold% of pointers and NULLs
        real_threshold = min(
            base_pointers_length - 1, 
            threshold * base_pointers_length
        )
        near_pointers = {
            offset:(set(ptrs), null_pointers_number_by_offset[offset]) 
            for offset, ptrs in visited_pointers.items() 
            if len(ptrs) + null_pointers_number_by_offset.get(offset, 0) >= real_threshold
        }

        self.near_pointers = near_pointers
        self.mode_distance = common_distance
        self.near_pointers_threshold = threshold

    def identify_structure_start(self, max_offset:int = 8192, threshold:float = 0.9) -> tuple[int, list[int]]:
        """
        Identify possible exact start of the structure using pointers which point to
        the start of other structure of the same topology (example struct
        task_struct *parent pointer in Linux task_struct). Return possible struct
        start and pointers offsets with share the same difference between associated
        pointers and base_ptrs
        """
        base_ptrs_array = np.array(self.pointers_list, dtype=np.uint64)
        offset_minimum_distance:dict[int, int] = {}
        distances:dict[int, int] = dict()

        for offset, (pointers_set, _) in self.near_pointers.items():
            
            # Ignore structural offsets, these offsets return always a distance of 0
            # from the start base pointers
            if offset in self.structural_offsets:
                continue

            # Find all the destination of pointers (excluding auto pointers) at a fixed offset, if those
            # pointers point to the starts of same type structures of the structure
            # under analysis there will be an common offset (at least in threshold%
            # of the cases)
            destination_pointers = [
                self.pointers[pointer] 
                for pointer in pointers_set 
                if pointer not in self.autopointers_set
            ]

            # Ignore offsets containing only autopointers
            if not destination_pointers: 
                continue

            # Collect for each pointer the minimum distance between its destination and all the base pointers
            minimum_distances = [
                self.uint_conversion_function(int(np.min(base_ptrs_array - pointer))) 
                for pointer in destination_pointers
            ] 
            if not minimum_distances:
                continue
            common_distance = Counter(minimum_distances).most_common(1)[0]
            distance, count = common_distance
            if count < min(threshold * len(pointers_set), len(pointers_set) - 1):
                continue
            if distance >= max_offset:
                continue
            if -distance > offset:
                continue
            if not (-distance <= offset <= -distance + self.mode_distance - self.pointer_size):
                continue

            offset_minimum_distance[offset] = distance
            if distance not in distances.keys():
                distances[distance] = 0
            distances[distance] += count
        
        # Consider all the offset at the same time, the common distance among them
        # could be the structure start referring to base ptrs offset
        if offset_minimum_distance:
            possible_starting_distance = sorted(
                distances.items(), 
                key=lambda offset_distance: (offset_distance[1], offset_distance[0])
            )[-1][0]
            homologous_near_pointers = [
                offset for offset, distance in offset_minimum_distance.items() 
                if distance == possible_starting_distance
            ]
        else:
            return -max_offset, []

        # Check if te structure starting at possible_start contains all the
        # structural offsets
        possible_starting_distance = -possible_starting_distance
        if possible_starting_distance > 0:
            return possible_starting_distance, [] 
        if not (possible_starting_distance  <= min(self.structural_offsets) <= max(self.structural_offsets) <= possible_starting_distance + self.mode_distance - self.pointer_size):
            return possible_starting_distance, []
        if any([
            not (possible_starting_distance  <= pointer <= possible_starting_distance + self.mode_distance - self.pointer_size) 
            for pointer in homologous_near_pointers
        ]):
            return possible_starting_distance, []
        
        homologous_near_pointers.sort()
        return possible_starting_distance, homologous_near_pointers

    def estimate_align(self, threshold:float = 0.5) -> tuple[int, int]:
        """
        Estimate the alignment of the structure inside the window, returns valid offsets
        """
        valid_pointers_per_window:list[float] = []

        # Consider only offsets with at least threshold% of not null pointers
        offsets = sorted([
            offset for offset, pointers in self.near_pointers.items()
            if (abs(offset-max(self.structural_offsets) - self.pointer_size) <= self.mode_distance and
                abs(offset-min(self.structural_offsets)) <= self.mode_distance and
                1 - pointers[1]/len(pointers[0]) > min(threshold, 1 - 1/len(pointers[0]))
            ) or offset in self.structural_offsets
        ])
        pointers_lengths = [
            len(self.near_pointers[offset][0]) 
            for offset in offsets
        ]
        
        final_index = bisect_left(offsets, min(self.structural_offsets) + 1)
                
        for index in range(0, final_index):
            total = 0
            offsets_counter = 0
            limit = offsets[index] + self.mode_distance - self.pointer_size

            for index_2 in range(index, final_index):
                if offsets[index_2] > limit:
                    break
                total += pointers_lengths[index_2]
                offsets_counter += 1
            try:
                valid_pointers_per_window.append(total/offsets_counter)
            except:
                valid_pointers_per_window.append(0)
        
        if not valid_pointers_per_window:
            return -1, -1

        start_index = valid_pointers_per_window.index(max(valid_pointers_per_window))
        
        return offsets[start_index], self.mode_distance

    def find_strings(self, threshold:float = 0.9) -> None:
        """
        Find pointed and embedded strings
        """
        base_pointers_length = len(self.pointers_list)
        strings_count = len(self.strings)

        embedded_strings:dict[int, list[int]] = dict()
        pointed_strings:dict[int, list[int]] = dict()

        for pointer in self.pointers_list:

            # Find pointed strings
            for offset in self.valid_near_offsets:
                address = pointer + offset
                if address in self.autopointers_set:
                    continue
                try:
                    pointed_address = self.pointers[address]
                    if pointed_address not in self.strings:
                        continue
                    if offset not in pointed_strings.keys():
                        pointed_strings[offset] = []
                    pointed_strings[offset].append(pointed_address)
                except KeyError:
                    pass
            
            # Find embedded strings
            minimum_address = pointer + self.shape[0]
            minimum_index = bisect_right(self.sorted_strings, minimum_address)
        
            for index in range(minimum_index, strings_count):
                difference = self.sorted_strings[index] - pointer

                if difference >= self.shape[0] + self.shape[1]:
                    break
                
                if difference not in embedded_strings.keys():
                    embedded_strings[difference] = []

                embedded_strings[difference].append(self.sorted_strings[index])


        real_threshold = min(
            base_pointers_length - 1, 
            threshold * base_pointers_length
        )
        for offset, collected_strings in pointed_strings.items():
            minimum_expected_length = min(
                len(self.near_pointers[offset]) - 1, 
                threshold * len(self.near_pointers[offset])
            )
            if len(collected_strings) <  minimum_expected_length: 
                continue
            if len(collected_strings) <= 2:
                continue
            self.pointed_strings[offset] = collected_strings

        for difference, collected_strings in embedded_strings.items():
            if len(collected_strings) < real_threshold:
                continue 
            if len(collected_strings) <= 2:
                continue
            self.embedded_strings[difference] = collected_strings
            
    def find_similar_string(self, string:str) -> tuple[tuple[int, bool], ...]:
        """
        Look if a similar string is pointed or embedded in the data structure
        """
        results:dict[tuple[int, bool], str] = {}
        string = string.lower()
        for offset, strings_addresses in self.embedded_strings.items():
            for string_address in strings_addresses:
                full_string = self.strings[string_address]
                if string in full_string:
                    results[(offset, False)] = full_string

        for offset, strings_addresses in self.pointed_strings.items():
            for string_address in strings_addresses:
                full_string = self.strings[string_address]
                if string in full_string:
                    results[(offset, True)] = full_string

        return tuple(results)

    def extract_strings(self, offset:int, is_pointed:bool) -> list[str]:
        if is_pointed:
            return [
                self.strings[pointer] 
                for pointer in self.pointed_strings[offset]
            ]
        else:
            return [
                self.strings[pointer] 
                for pointer in self.embedded_strings[offset]
            ]

class LinkedList(PointersGroup):
    
    # Attributes type hinting
    is_terminated: bool
    is_cyclic: bool

    def __init__(self, base_pointers:list[int], offsets:tuple[int], is_cyclic: bool) -> None:
        super().__init__(base_pointers, offsets)
        self.is_terminated = self.does_list_finish()
        self.is_cyclic = is_cyclic

    def does_list_finish(self) -> bool:
        """
        Return True if the list is terminated (NULL or autoptrs ending), False (data ending) otherwise
        """
        if self.pointers_list[-1] in self.autopointers_set:
            return True

        try:
            dereferencing_pointer = self.pointers[self.pointers_list[-1]] + self.destination_offsets[0]
            if dereferencing_pointer  == self.pointers_list[-1]:
                return True

            elf_dump_offset = self.virtual_to_offset[dereferencing_pointer]
            if elf_dump_offset == -1 or self.bitmap[elf_dump_offset:elf_dump_offset + self.pointer_size].any():
                return False
        except:
            pass

        elf_dump_offset = self.virtual_to_offset[self.pointers_list[-1]]
        if elf_dump_offset == -1 or self.bitmap[elf_dump_offset:elf_dump_offset + self.pointer_size].any():
            return False
        else:
            return True
        
class DoubleLinkedList(PointersGroup):

    # Attributes type hinting
    inverse_pointers_list: list[int]
    is_degenerate: bool
    is_cyclic: bool

    def __init__(self, base_pointers:list[int], inverse_pointers:list[int], offsets: tuple[int, int], is_cyclic:bool):
        structure_distance = base_pointers[0] - inverse_pointers[-1]
        if structure_distance < 0:
            super().__init__(base_pointers, offsets)
            self.inverse_pointers_list = inverse_pointers
        else:
            super().__init__(inverse_pointers, offsets[::-1])
            self.inverse_pointers_list = base_pointers

        # Offsets of next and prev pointers
        self.structural_offsets = set((0, abs(structure_distance))) 
        offsets_distance = abs( abs(int(offsets[0])) - abs(int(offsets[1])) )

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
        self.is_degenerate = abs(structure_distance) != offsets_distance
        self.is_ciclic = is_cyclic

class Tree(PointersGroup):

    # Attributes type hinting
    nodes: list[int|None]
    levels: int

    def __init__(self, base_pointers:list[int|None], offsets:tuple[int,int], levels:int) -> None:
        self.nodes = base_pointers
        pointers = [pointer for pointer in base_pointers if pointer is not None]
        super().__init__(pointers, offsets)
        self.levels = levels

    def get_tree_embedded_strings(self, offset:int) -> list[int]:
        strings_addresses = []
        for pointer in self.nodes:
            if pointer and pointer + offset in self.embedded_strings[offset]:
                strings_addresses.append(pointer + offset)
            else:
                strings_addresses.append(None)
        return strings_addresses

    def get_tree_pointed_strings(self, offset: int) -> list[int]:
        strings_addresses = []
        for pointer in self.nodes:
            try:
                if pointer and self.pointers[pointer + offset] in self.pointed_strings[offset]:
                    strings_addresses.append(self.pointers[pointer + offset])
                else:
                    strings_addresses.append(None)
            except Exception as e:
                print(e)
                strings_addresses.append(None)
        return strings_addresses

class PointersArray(MemoryObject):

    # Attributes type hinting
    pointers_list: list[int]
    referenced: bool
    structure: PointersGroup|None
    referenced_functions: bool
    strings_array: list[int]

    def __init__(self, pointers_list: list[int]) -> None:
        self.pointers_list = pointers_list
        destination_pointers = {self.pointers[pointer] for pointer in pointers_list}
        self.referenced = bool(self.external_references.intersection(self.pointers_list))
        self.structure = None
        self.referenced_functions = bool(self.functions.intersection(self.pointers_list))

        # Find if all the pointers point directly to strings
        if destination_pointers.issubset(self.strings_set):
            self.strings_array = list(destination_pointers)
        else:
            self.strings_array = []
            if len(destination_pointers) > 2:
                # Struct pointed by pointers
                self.structure = PointersGroup(list(destination_pointers))     
                
                # Treat as a struct Test *array[XX] (array of pointer to structs)
                self.structure.determine_shape()
                if self.structure.shape != (-1, -1):
                    self.structure.find_strings() # <= the strings at offset 0 corresponds to char **array[XX] (array of double pointers to char) or an array of pointer to structs with field 0 as char *
                    self.structure.find_ip_addresses()
