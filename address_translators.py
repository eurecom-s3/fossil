import logging
import numpy as np

from bitarray import bitarray
from mappings import (
    IntervalsMappingOffsets,
    IntervalsMappingOverlapping,
    IntervalsMappingData
)
from memory_objects import ELFDump
from struct import iter_unpack
from tqdm import tqdm
from typing import Any, Callable

#################
# Typing        #
#################
MappingType = dict[tuple[int, int, int], list[tuple[int, int, int, bool]]]
ReverseMappingType = dict[tuple[int, int, int], dict[tuple[int, int], list[int]]]

#################
# Base Class    #
#################
class AddressTranslator:

    # Attributes type hinting
    wordsize: int
    table_address:int
    elf_dump: ELFDump
    word_type: type
    word_format: np.dtype
    virtual_to_offset: IntervalsMappingOffsets
    offset_to_virtual: IntervalsMappingOverlapping
    permissions_mask: IntervalsMappingData
    total_levels: int
    table_sizes: list[int]
    ignored_pages: list[int]
    unpack_format: str
    shifts: list[int]
    mapping: MappingType
    reverse_mapping: ReverseMappingType
    memory_bitmap: bitarray
    pointers: dict[int, int]
    reverse_pointers: dict[int, list[int]]
    strings: dict[int, str]
    minimum_page: int

    # Derived functions type hinting
    _read_entry: Callable[[int, int, int], tuple[bool, list[list[bool]], int, int]]
    _reconstruct_permissions: Callable[[list[list[bool]]], tuple[int, int, int]]
    _finalize_virtual_address: Callable[[int, tuple[int, int, int]], int]

    def __init__(self, table_address:int, elf_dump:ELFDump) -> None:
        self.table_address = table_address
        self.elf_dump = elf_dump

        # Set machine specifics
        if self.wordsize == 4:
            self.word_type = np.uint32
            if self.elf_dump.machine_data['Endianness'] == 'big':
                self.word_format = np.dtype('>u4')
            else:
                self.word_format = np.dtype('<u4')
        else:
            self.word_type = np.uint64
            if self.elf_dump.machine_data['Endianness'] == 'big':
                self.word_format = np.dtype('>u8')
            else:
                self.word_format = np.dtype('<u8')

    def _explore_radixtree(
        self, 
        table_address:int, 
        mapping:MappingType, 
        reverse_mapping:ReverseMappingType, 
        level:int = 0, 
        prefix:int = 0, 
        user_permissions_mask:list[list[bool]] = [[]]
    ) -> tuple[MappingType, ReverseMappingType]:
        """
        Explores the radix tree 
        Returns virtual <-> physical mappings
        Returns:
            - mapping
            - reverse_mapping
        """
        # Get table
        i = '\t' * level
        logging.debug(f'{i}{hex(table_address)} {level}/{self.total_levels - 1}')
        table = self.elf_dump.get_data(table_address, self.table_sizes[level])
        if not table:
            print(f'Table {hex(table_address)} size:{self.table_sizes[level]} at level {level} not in RAM')
            return mapping, reverse_mapping

        # Ignore physical pages used as placeholders
        if table_address in self.ignored_pages and level == self.total_levels - 1:
            logging.debug(f'Ignoring {hex(table_address)}')
            return mapping, reverse_mapping

        for index, entry in enumerate(iter_unpack(self.unpack_format, table)):
            is_valid, permissions_mask, physical_address, page_size = self._read_entry(index, entry[0], level)
            if not is_valid:
                continue

            virtual_address = prefix | (index << self.shifts[level])
            permissions_mask = user_permissions_mask + permissions_mask

            if (level == self.total_levels - 1) or page_size: # Last radix level or Leaf
                # Ignore pages not in RAM (some OSs map more RAM than available) and not memory mapped devices
                in_ram = self.elf_dump.in_ram(physical_address, page_size)
                in_memory_mapped_device = self.elf_dump.in_memory_mapped_device(physical_address, page_size)
                if not in_ram and not in_memory_mapped_device:
                    continue

                permissions = self._reconstruct_permissions(permissions_mask)
                virtual_address = self._finalize_virtual_address(virtual_address, permissions)
                if permissions not in mapping.keys():
                    mapping[permissions] = []
                mapping[permissions].append((virtual_address, page_size, physical_address, in_memory_mapped_device))

                # Add only RAM address to the reverse translation P2V
                if in_ram and not in_memory_mapped_device:
                    if permissions not in reverse_mapping.keys():
                        reverse_mapping[permissions] = dict()
                    if (physical_address, page_size) not in reverse_mapping[permissions].keys():
                        reverse_mapping[permissions][(physical_address, page_size)] = []
                    reverse_mapping[permissions][(physical_address, page_size)].append(virtual_address)
            else:
                # Lower level entry
                mapping, reverse_mapping =  self._explore_radixtree(physical_address, mapping, reverse_mapping, level=level+1, prefix=virtual_address, user_permissions_mask=permissions_mask)
        return mapping, reverse_mapping

    def _compact_intervals_virt_offset(self, intervals:list[tuple[int, int, int, tuple[int, int, int]]]) -> list[tuple[int, tuple[int, int]]]:
        """
        Compact intervals if virtual addresses and offsets values are
        contiguous (virt -> offset)
        """
        fused_intervals:list[tuple[int, tuple[int, int]]] = []
        prev_begin = prev_end = prev_offset = -1
        begin = end = physical = -1

        for interval in intervals:
            begin, end, physical, _ = interval
            offset = self.elf_dump.physical_to_offset[physical]
            if offset == -1:
                continue

            if prev_end == begin and prev_offset + (prev_end - prev_begin) == offset:
                prev_end = end
            else:
                fused_intervals.append((prev_begin, (prev_end, prev_offset)))
                prev_begin = begin
                prev_end = end
                prev_offset = offset
        
        if prev_begin != begin:
            fused_intervals.append((prev_begin, (prev_end, prev_offset)))
        else:
            offset = self.elf_dump.physical_to_offset[physical]
            if offset == -1:
                print(f"ERROR!! {physical}")
            else:
                fused_intervals.append((begin, (end, offset)))
        return fused_intervals[1:]

    def _compact_intervals_permissions(self, intervals:list[tuple[int, int, int, tuple[int, int, int]]]) -> list[tuple[int, tuple[int, tuple[int, int, int]]]]:
        """
        Compact intervals if virtual addresses are contigous and permissions are equals
        """

        fused_intervals:list[tuple[int, tuple[int, tuple[int, int, int]]]] = []
        prev_begin = prev_end = -1
        begin = end = -1
        permission_mask = prev_permission_mask = (0, 0, 0)

        for interval in intervals:
            begin, end, _, permission_mask = interval            
            if prev_end == begin and prev_permission_mask == permission_mask:
                prev_end = end
            else:
                fused_intervals.append((prev_begin, (prev_end, prev_permission_mask)))
                prev_begin = begin
                prev_end = end
                prev_permission_mask = permission_mask
        
        if prev_begin != begin:
            fused_intervals.append((prev_begin, (prev_end, prev_permission_mask)))
        else:
            fused_intervals.append((begin, (end, permission_mask)))

        return fused_intervals[1:]

    def _reconstruct_mappings(self, table_address:int, user_permissions_mask:list[list[bool]]) -> None:
        # Explore the radix tree
        mapping:MappingType = dict()
        reverse_mapping:ReverseMappingType = dict()

        mapping, reverse_mapping = self._explore_radixtree(
            table_address, 
            mapping, 
            reverse_mapping, 
            user_permissions_mask=user_permissions_mask
        )

        # Needed for ELF virtual mapping reconstruction
        self.reverse_mapping = reverse_mapping
        self.mapping = mapping

        # Collect all intervals (start, end+1, phy_page, pmask)
        intervals:list[tuple[int, int, int, tuple[int, int, int]]] = []
        for permissions_mask, mapped_values in mapping.items():
            if permissions_mask[0] == 0: # Ignore user accessible pages
                continue
            intervals.extend([
                (interval[0], interval[0] + interval[1], interval[2], permissions_mask) 
                for interval in mapped_values 
                if not interval[3]
            ]) # Ignore MMD
        intervals.sort()

        # Fuse intervals in order to reduce the number of elements to speed up
        fused_intervals_virtual_to_offset = self._compact_intervals_virt_offset(intervals)
        fused_intervals_permissions = self._compact_intervals_permissions(intervals)
        
        # Offset to virtual is impossible to compact in a easy way due to the
        # multiple-to-one mapping. We order the array and use bisection to find
        # the possible results and a partial 
        intervals_offest_to_virtual:list[tuple[int, int, tuple[int, ...]]] = []
        for permissions_mask, interval in reverse_mapping.items():
            if permissions_mask[0] == 0: # Ignore user accessible pages
                continue
            for key, value in interval.items():
                # We have to translate phy -> offset
                offset = self.elf_dump.physical_to_offset[key[0]]
                if offset == -1: # Ignore unresolvable pages
                    continue
                intervals_offest_to_virtual.append((offset, key[1] + offset, tuple(value)))
        intervals_offest_to_virtual.sort()

        # Fill resolution objects
        self.virtual_to_offset = IntervalsMappingOffsets(*list(zip(*fused_intervals_virtual_to_offset)))
        self.offset_to_virtual = IntervalsMappingOverlapping(intervals_offest_to_virtual)
        self.permissions_mask  = IntervalsMappingData(*list(zip(*fused_intervals_permissions)))

    def create_bitmap(self) -> None:
        """
        Create a bitmap starting from the ELF file containing 0 if the byte
        is 0, 1 otherwise
        """
        print("Creating bitmap...")
        self.memory_bitmap = bitarray()
        self.memory_bitmap.pack(self.elf_dump.elf_buffer.tobytes())

    def _find_pointers_align(self, alignment:int) -> dict[int, int]:
        """
        For a fixed align retrieve all valid pointers in dump
        """

        # Workaround for alignment
        aligned_length = self.elf_dump.elf_buffer.shape[0] - (self.elf_dump.elf_buffer.shape[0] % self.wordsize)
    
        if alignment == 0:
            end = aligned_length
        else:
            end = aligned_length - (self.wordsize - alignment)

        # Find all destination addresses which could be valid kernel addresses ignoring too
        # little or too big ones (src -> dst)
        word_array = self.elf_dump.elf_buffer[alignment:end].view(self.word_format)
        min_virtual, max_virtual = self.virtual_to_offset.get_extremes()
        logging.debug(f"Min virtual address: {hex(min_virtual)}, Max virtual address: {hex(max_virtual)}") 
        destinations_index = np.where((word_array >= min_virtual) & (word_array <= max_virtual))[0]
        destinations = word_array[destinations_index]
        sources_offsets = (destinations_index * self.wordsize) + alignment # This array contains the offset on the file of the dst candidates (the src of the pointer!)
        pointers:dict[int,int] = {}

        for index, destination in enumerate(tqdm(destinations)):
            # Validate dsts
            destination = int(destination) # All this conversion is due to a numpy "feature" https://github.com/numpy/numpy/issues/5745
            if self.virtual_to_offset[destination] == -1:
                continue

            # Validate srcs
            sources_list = self.offset_to_virtual[int(sources_offsets[index])]
            if len(sources_list) > 0:
                for source in sources_list:
                    pointers[source] = destination
        
        return pointers

    def retrieve_pointers(self) -> None:
        print('Retrieving pointers...')
        direct_map:dict[int, int] = dict()   # virt1 -> virt2        location virt1 point to virt2 one-to-one
        reverse_map:dict[int, list[int]] = dict()  # virt2 -> [virt1, ...] location at virt2 is pointed by [virt1, ...] one-to-many

        # Monothread not super optimized but it's fast :D (thanks Matteo)
        pointers:dict[int, int] = dict()

        for alignment in range(self.wordsize):
            print(f'Look for pointers with alignement {alignment}...')
            new_pointers = self._find_pointers_align(alignment)
            print(f'Found {len(new_pointers)} new pointers')
            pointers.update(new_pointers)

        # Reconstruct dict
        direct_map.update(pointers)
        for source, destination in pointers.items():
            if destination not in reverse_map.keys():
                reverse_map[destination] = []
            reverse_map[destination].append(source)

        self.pointers = direct_map
        self.reverse_pointers = reverse_map

    def retrieve_strings(self, min_length:int = 3, max_symbols_threshold:float = 0.3) -> None:
        # Get strings with physical addresses [(string, paddr), ...]
        print("Retrieving strings...")
        strings:dict[int, str] = dict()
        strings_offsets = self.elf_dump.retrieve_strings_offsets(min_length)
        # rw_strings = []

        for string in strings_offsets:
            value, offset = string

            # Ignore strings which are not part of the memory dump (eg, ELF dump constants etc.)
            virtual_addresses = self.offset_to_virtual[offset]
            if not virtual_addresses:
                continue
            
            for virtual_address in virtual_addresses:
                # HEURISTICS if there are more than max_symbol_threshold
                # symbols ignore it
                if sum(not char.isalnum() for char in value)/len(value) >= max_symbols_threshold:
                    continue
                strings[virtual_address] = value

                # Add substrings referenced by pointers
                for i in range(1, len(value)):
                    substring_virtual_address = i + virtual_address
                    if substring_virtual_address in self.reverse_pointers:
                        # HEURISTICS if there are more than max_symbol_threshold
                        # symbols percentage ignore it
                        if sum(not char.isalnum() for char in value[i:])/len(value[i:]) >= max_symbols_threshold:
                            continue
                        strings[substring_virtual_address] = value[i:]

        self.strings = strings
        # self.rw_strings = set(rw_strings)

    def export_virtual_memory_elf(
        self, 
        elf_filename:str, 
        kernel:bool = True, 
        only_executable:bool = False, 
        ignore_empties:bool = True
    ) -> None:
        """
        Create an ELF file containg the virtual address space of the kernel/process
        """
        
        print('Converting dump to virtual addresses ELF...')
        with open(elf_filename, 'wb') as elf_fd:
            # Create the ELF header and write it on the file
            machine_data = self.elf_dump.get_machine_data()
            endianness = machine_data['Endianness']
            machine = machine_data['Architecture'].lower()

            # Create ELF main header
            if 'aarch64' in machine:
                e_machine = 0xB7
            elif 'arm' in machine:
                e_machine = 0x28
            elif 'riscv' in machine:
                e_machine = 0xF3
            elif 'x86_64' in machine:
                e_machine = 0x3E
            elif '386' in machine:
                e_machine = 0x03
            else:
                raise Exception('Unknown architecture')

            e_ehsize = 0x40
            e_phentsize = 0x38
            elf_h = bytearray(e_ehsize)
            elf_h[0x00:0x04] = b'\x7fELF'                                   # Magic
            elf_h[0x04] = 2                                                 # Elf type
            elf_h[0x05] = 1 if endianness == 'little' else 2                # Endianness
            elf_h[0x06] = 1                                                 # Version
            elf_h[0x10:0x12] = 0x4.to_bytes(2, endianness)                  # e_type
            elf_h[0x12:0x14] = e_machine.to_bytes(2, endianness)            # e_machine
            elf_h[0x14:0x18] = 0x1.to_bytes(4, endianness)                  # e_version
            elf_h[0x34:0x36] = e_ehsize.to_bytes(2, endianness)             # e_ehsize
            elf_h[0x36:0x38] = e_phentsize.to_bytes(2, endianness)          # e_phentsize
            elf_fd.write(elf_h)

            # For each pmask try to compact intervals in order to reduce the number of segments
            intervals:dict[int, list[tuple[int, int, int]]] = dict()
            for permissions_mask, intervals_list in self.mapping.items():
                
                if not(bool(permissions_mask[1]) ^ kernel): # Select only kernel/process mappings
                    continue
                
                if kernel:
                    permission_mask = permissions_mask[0]
                else:
                    permission_mask = permissions_mask[1]
                
                if only_executable and not(bool(permission_mask & 0x1)): # Select only/all executable mappings
                    continue
                
                if ignore_empties:
                    for interval in intervals_list:
                        if interval[3]: # Ignore MMD
                            continue
                        offset = self.virtual_to_offset[interval[0]]
                        if offset == -1:
                            continue
                        if not any(self.elf_dump.elf_buffer[offset:offset+interval[1]]): # Filter for empty pages
                            continue
                        if not permission_mask in intervals.keys():
                            intervals[permission_mask] = []
                        intervals[permission_mask].append((interval[0], interval[0]+interval[1], interval[2]))
                else:
                    intervals[permission_mask].extend([
                        (interval[0], interval[0]+interval[1], interval[2]) 
                        for interval in intervals_list 
                        if not interval[3]
                    ]) # Ignore MMD

                intervals[permission_mask].sort()

                # Compact them
                fused_intervals:list[tuple[int, int, int]] = []
                prev_begin = prev_end = prev_offset = -1
                begin = end = physical = -1
                for interval in intervals[permission_mask]:
                    begin, end, physical = interval

                    offset = self.elf_dump.physical_to_offset[physical]
                    if offset == -1:
                        continue

                    if prev_end == begin and prev_offset + (prev_end - prev_begin) == offset:
                        prev_end = end
                    else:
                        fused_intervals.append((prev_begin, prev_end, prev_offset))
                        prev_begin = begin
                        prev_end = end
                        prev_offset = offset

                if prev_begin != begin:
                    fused_intervals.append((prev_begin, prev_end, prev_offset))
                else:
                    offset = self.elf_dump.physical_to_offset[physical]
                    if offset == -1:
                        print(f"ERROR!! {physical}")
                    else:
                        fused_intervals.append((begin, end, offset))
                intervals[permission_mask] = sorted(fused_intervals[1:], key=lambda x: x[1] - x[0], reverse=True)
            
            # Write segments in the new file and fill the program header
            physical_offset = len(elf_h)
            offset_to_physical_offset:dict[int, int] = dict() # Slow but more easy to implement (best way: a tree sort structure able to be updated)
            elf_physical_total = 0
            
            new_intervals:dict[int, list[tuple[int, int, int, int]]] = dict()
            for permission_mask, intervals_list in intervals.items():
                elf_physical_total += len(intervals_list)
                
                new_intervals_list:list[tuple[int, int, int, int]] = []
                for interval in intervals_list:
                    begin, end, offset = interval
                    size = end - begin

                    if offset not in offset_to_physical_offset:
                        elf_fd.write(self.elf_dump.get_raw_data(offset, size))

                        if not self.elf_dump.get_raw_data(offset, size):
                            print(hex(offset), hex(size))

                        new_offset = physical_offset 
                        physical_offset += size
                        for page_index in range(0, size, self.minimum_page):
                            offset_to_physical_offset[offset + page_index] = new_offset + page_index
                    else:
                        new_offset = offset_to_physical_offset[offset]
                    new_intervals_list.append((begin, end, offset, new_offset))
                    # Assign the new offset in the dest file
                new_intervals[permission_mask] = new_intervals_list
                
            # Create the program header containing all the segments (ignoring not in RAM pages)
            e_phoff = elf_fd.tell()
            p_header = bytes()
            for permission_mask, intervals_list in new_intervals.items():
                for begin, end, offset, physical_offset in intervals_list:
                    
                    # Workaround Ghidra 32 bit
                    if end == 0xFFFFFFFF + 1 and e_machine == 0x03:
                        end = 0xFFFFFFFF
                    
                    p_filesz = end - begin

                    segment_entry = bytearray(e_phentsize)
                    segment_entry[0x00:0x04] = 0x1.to_bytes(4, endianness)          # p_type
                    segment_entry[0x04:0x08] = permission_mask.to_bytes(4, endianness)        # p_flags
                    segment_entry[0x10:0x18] = begin.to_bytes(8, endianness)        # p_vaddr
                    segment_entry[0x18:0x20] = offset.to_bytes(8, endianness)       # p_paddr Original offset
                    segment_entry[0x28:0x30] = p_filesz.to_bytes(8, endianness)     # p_memsz
                    segment_entry[0x08:0x10] = physical_offset.to_bytes(8, endianness)     # p_offset
                    segment_entry[0x20:0x28] = p_filesz.to_bytes(8, endianness)     # p_filesz

                    p_header += segment_entry

            # Write the segment header
            elf_fd.write(p_header)
            s_header_pos = elf_fd.tell() # Last position written (used if we need to write segment header)

            # Modify the ELF header to point to program header
            elf_fd.seek(0x20)
            elf_fd.write(e_phoff.to_bytes(8, endianness))             # e_phoff

            # If we have more than 65535 segments we have create a special Section entry contains the
            # number of program entry (as specified in ELF64 specifications)
            if elf_physical_total < 65536:
                elf_fd.seek(0x38)
                elf_fd.write(elf_physical_total.to_bytes(2, endianness))         # e_phnum
            else:
                elf_fd.seek(0x28)
                elf_fd.write(s_header_pos.to_bytes(8, endianness))    # e_shoff
                elf_fd.seek(0x38)
                elf_fd.write(0xFFFF.to_bytes(2, endianness))          # e_phnum
                elf_fd.write(0x40.to_bytes(2, endianness))            # e_shentsize
                elf_fd.write(0x1.to_bytes(2, endianness))             # e_shnum

                section_entry = bytearray(0x40)
                section_entry[0x2C:0x30] = elf_physical_total.to_bytes(4, endianness)  # sh_info
                elf_fd.seek(s_header_pos)
                elf_fd.write(section_entry)

#########
# Intel #
#########
class IntelTranslator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(mmu_class:type, registers:dict[str, int], max_physical_address:int, ignored_pages:list[int]) -> dict[str, int|bool|list[int]]:
        if mmu_class is IntelAMD64:
            dtb = ((registers['cr3'] >> 12) & ((1 << (max_physical_address - 12)) - 1)) << 12

        elif mmu_class is IntelPAE:
            dtb = ((registers['cr3'] >> 5) & (1 << 27) - 1) << 5

        elif mmu_class is IntelIA32:
            dtb = ((registers['cr3'] >> 12) & (1 << 20) - 1) << 12
            max_physical_address = min(max_physical_address, 40)

        else:
            raise NotImplementedError

        return {
            'table_address': dtb,
            'wp':  bool((registers['cr0'] >> 16) & 0x1),
            'ac':  bool((registers['eflags'] >> 18) & 0x1),
            'nxe': bool((registers['efer'] >> 11) & 0x1),
            'smep': bool((registers['cr4'] >> 20) & 0x1),
            'smap': bool((registers['cr4'] >> 21) & 0x1),
            'max_physical_address': max_physical_address,
            'ignored_pages': ignored_pages
        }

    @staticmethod
    def derive_translator_class(registers:dict[str, int]) -> type:
        pg =  bool((registers['cr0']  >> 31) & 0x1)
        pae = bool((registers['cr4']  >> 5)  & 0x1)
        lme = bool((registers['efer'] >> 8)  & 0x1)

        if pg and pae and lme:
            return IntelAMD64
        elif pg and pae:
            return IntelPAE
        elif pg:
            return IntelIA32
        else:
            raise NotImplementedError

    def __init__(
        self, 
        table_address:int, 
        elf_dump:ELFDump, 
        max_physical_address:int, 
        wp:bool = False, 
        ac:bool = False, 
        nxe:bool = False, 
        smap:bool = False, 
        smep:bool = False
    ) -> None:
        super(IntelTranslator, self).__init__(table_address, elf_dump)
        self.mphy = max_physical_address
        self.wp = wp
        self.ac = ac # UNUSED by Fossil
        self.smap = smap
        self.nxe = nxe
        self.smep = smep
        self.minimum_page = 0x1000

        logging.debug(f"""
            Type: {type(self)}, 
            MAX_PHY: {self.mphy}, 
            WP {self.wp}, 
            AC {self.ac}, 
            SMAP {self.smap}, 
            SMEP {self.smep}, 
            NXE {self.nxe}, 
            DTB {hex(self.table_address)}
        """)

        print('Creating resolution trees...')
        self._reconstruct_mappings(self.table_address, user_permissions_mask=[[False, True, True]])

    def _finalize_virtual_address(self, virtual_address:int) -> int:
        return virtual_address

class IntelIA32(IntelTranslator):

    # Attributes type hinting
    unpack_format:str
    total_levels:int
    prefix:int
    table_sizes:list[int]
    shifts:list[int]
    wordsize:int
    ignored_pages:list[int]

    def __init__(
        self, 
        table_address:int, 
        elf_dump:ELFDump, 
        max_physical_address: int, 
        wp:bool = True, 
        ac:bool = False, 
        nxe:bool = False, 
        smap:bool = False, 
        smep:bool = False, 
        ignored_pages:list[int] = []
    ) -> None:
        self.unpack_format = '<I'
        self.total_levels = 2
        self.prefix = 0x0
        self.table_sizes = [0x1000, 0x1000]
        self.shifts = [22, 12]
        self.wordsize = 4
        self.ignored_pages = ignored_pages

        super(IntelIA32, self).__init__(table_address, elf_dump, max_physical_address, wp, ac, nxe, smap, smep)

    def _read_entry(self, index:int, entry:int, level:int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, [[]], 0, 0

        else:
            permission_flags = [[
                not bool(entry & 0x4),   # K
                bool(entry & 0x2),       # W
                True                     # X
            ]]

            # Upper tables pointers
            if not(entry & 0x80) and (level == 0):
                address = ((entry >> 12) & ((1 << 20) - 1)) << 12
                return True, permission_flags, address, 0

            # Leaf
            else:
                if level == 0:
                    address = (((entry >> 13) & ((1 << (self.mphy - 32)) - 1)) << 32) | (((entry >> 22) & ((1 << 10) - 1)) << 22)
                else:
                    address = ((entry >> 12) & ((1 << 20) - 1)) << 12
                return True, permission_flags, address, 1 << self.shifts[level]

    def _reconstruct_permissions(self, permissions_mask:list[list[bool]]) -> tuple[int, int]:
        kernel_flags, write_flags, _ = zip(*permissions_mask)
        kernel_flags: tuple[bool, ...]
        write_flags: tuple[bool, ...]

        # Kernel page in kernel mode
        if any(kernel_flags):
            read = True
            write = all(write_flags) if self.wp else True
            execute = True

            return read << 2 | write << 1 | int(execute), 0

        # User page in kernel mode
        else:
            read = True if (not self.smap) or (self.smap and self.ac) else False

            if not self.wp:
                write = True if (not self.smap) or (self.smap and self.ac) else False
            else:
                write = all(write_flags) if (not self.smap) or (self.smap and self.ac) else False

            execute = True

            return 0, read << 2 | write << 1 | int(execute)

class IntelPAE(IntelTranslator):
    def __init__(
        self, 
        table_address:int, 
        elf_dump:ELFDump, 
        max_physical_address:int, 
        wp:bool = True, 
        ac:bool = False, 
        nxe:bool = True, 
        smap:bool = False, 
        smep:bool = False, 
        ignored_pages:list[int] = []
    ) -> None:
        self.unpack_format = "<Q"
        self.total_levels = 3
        self.prefix = 0x0
        self.table_sizes = [0x20, 0x1000, 0x1000]
        self.shifts = [30, 21, 12]
        self.wordsize = 4
        self.ignored_pages = ignored_pages

        super(IntelPAE, self).__init__(table_address, elf_dump, max_physical_address, wp, ac, nxe, smap, smep)

    def _read_entry(self, index:int, entry:int, level:int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, [[]], 0, 0

        else:
            if level == 0:
                permissions_flag = [[False, True, True]]
            else:
                permissions_flag = [[ 
                    not bool(entry & 0x4),               # K
                    bool(entry & 0x2),                   # W
                    not bool(entry & 0x8000000000000000) # X
                ]]

            # Upper tables pointers
            if (not(entry & 0x80) and level < 2) or level == 0: # PDPTE does not have leaf
                address = ((entry >> 12) & ((1 << (self.mphy - 12)) - 1)) << 12
                return True, permissions_flag, address, 0

            # Leaf
            else:
                address = ((entry >> self.shifts[level]) & ((1 << (self.mphy - self.shifts[level])) - 1)) << self.shifts[level]
                return True, permissions_flag, address, 1 << self.shifts[level]

    def _reconstruct_permissions(self, permissions_mask:list[list[bool]]) -> tuple[int, int]:
        kernel_flags, write_flags, execute_flags = zip(*permissions_mask)
        kernel_flags: tuple[bool, ...]
        write_flags: tuple[bool, ...]
        execute_flags: tuple[bool, ...]

        # Kernel page in kernel mode
        if any(kernel_flags):
            read = True
            write = all(write_flags) if self.wp else True
            execute = all(execute_flags) if self.nxe else True

            return read << 2 | write << 1 | int(execute), 0

        # User page in kernel mode
        else:
            read = True if (not self.smap) or (self.smap and self.ac) else False

            if not self.wp:
                write = True if (not self.smap) or (self.smap and self.ac) else False
            else:
                write = all(write_flags) if (not self.smap) or (self.smap and self.ac) else False

            if not self.smep:
                execute = all(execute_flags) if self.nxe else True
            else:
                execute = False

            return 0, read << 2 | write << 1 | int(execute)

class IntelAMD64(IntelTranslator):
    def __init__(
        self, 
        table_address:int, 
        elf_dump: ELFDump, 
        max_physical_address: int, 
        wp:bool = True, 
        ac:bool = False, 
        nxe:bool = True, 
        smap:bool = False, 
        smep:bool = False, 
        ignored_pages:list[int] = []
    ) -> None:
        self.unpack_format = "<Q"
        self.total_levels = 4
        self.prefix = 0xFFFF800000000000
        self.table_sizes = [0x1000] * 4
        self.shifts = [39, 30, 21, 12]
        self.wordsize = 8
        self.ignored_pages = ignored_pages

        super(IntelAMD64, self).__init__(table_address, elf_dump, max_physical_address, wp, ac, nxe, smap, smep)

    def _read_entry(self, index:int, entry:int, level:int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, [[]], 0, 0

        else:
            permissions_flags = [[ 
                not bool(entry & 0x4),               # K
                bool(entry & 0x2),                   # W
                not bool(entry & 0x8000000000000000) # X
            ]]

            # Upper tables pointers
            if (not(entry & 0x80) and level < 3) or level == 0: # PTL4 does not have leaf
                address = ((entry >> 12) & ((1 << (self.mphy - 12)) - 1)) << 12
                return True, permissions_flags, address, 0

            # Leaf
            else:
                address = ((entry >> self.shifts[level]) & ((1 << (self.mphy - self.shifts[level])) - 1)) << self.shifts[level]
                return True, permissions_flags, address, 1 << self.shifts[level]

    def _reconstruct_permissions(self, permissions_mask:list[list[bool]]) -> tuple[int, int]:
        kernel_flags, write_flags, execute_flags = zip(*permissions_mask)
        kernel_flags: tuple[bool, ...]
        write_flags: tuple[bool, ...]
        execute_flags: tuple[bool, ...]

        # Kernel page in kernel mode
        if any(kernel_flags):
            read = True
            write = all(write_flags) if self.wp else True
            execute = all(execute_flags) if self.nxe else True

            return read << 2 | write << 1 | int(execute), 0

        # User page in kernel mode
        else:
            read = True if (not self.smap) or (self.smap and self.ac) else False

            if not self.wp:
                write = True if (not self.smap) or (self.smap and self.ac) else False
            else:
                write = all(write_flags) if (not self.smap) or (self.smap and self.ac) else False

            if not self.smep:
                execute = all(execute_flags) if self.nxe else True
            else:
                execute = False

            return 0, read << 2 | write << 1 | int(execute)

    def _finalize_virtual_address(self, virtual_address:int, permissions:tuple[int, int, int]) -> int:
        # Canonical address form
        if virtual_address & 0x800000000000:
            return self.prefix | virtual_address
        else:
            return virtual_address

#########
# RISCV #
#########
class RISCVTranslator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(mmu_class:type, registers:dict[str, int], ignored_pages:list[int]) -> dict[str, int|bool|list[int]]:
        if mmu_class is RISCVSV32:
            dtb = (registers['satp'] & ((1 << 22) - 1)) << 12
        elif mmu_class is RISCVSV39:
            dtb = (registers['satp'] & ((1 << 44) - 1)) << 12
        else:
            raise NotImplementedError

        return {
            'table_address': dtb,
            'Sum':  bool((registers['sstatus'] >> 18) & 0x1),
            'mxr': bool((registers['sstatus'] >> 19) & 0x1),
            'ignored_pages': ignored_pages
        }

    @staticmethod
    def derive_translator_class(registers:dict[str, int]) -> type:
        satp = registers['satp']

        mode32 = (satp >> 31) & 0x1
        mode64 = (satp >> 60) & 0x0F

        if mode64 == 8:
            return RISCVSV39
        elif mode64 > 0:
            raise NotImplementedError

        if not mode64 and mode32:
            return RISCVSV32
        else:
            raise NotImplementedError

    def __init__(self, table_address:int, elf_dump:ELFDump, Sum:bool = True, mxr:bool = True) -> None:
        super(RISCVTranslator, self).__init__(table_address, elf_dump)
        self.Sum = Sum
        self.mxr = mxr
        self.minimum_page = 0x1000

        print('Creating resolution trees...')
        self._reconstruct_mappings(self.table_address, user_permissions_mask=[[False, True, True, True]])

    def _finalize_virtual_address(self, virtual_address:int) -> int:
        return virtual_address

    def _reconstruct_permissions(self, permissions_mask:list[list[bool]]) -> tuple[int, int]:
        k_flag, r_flag, w_flag, x_flag = permissions_mask[-1] # No hierarchy

        r = r_flag
        if self.mxr:
            r |= x_flag

        w = w_flag
        x = x_flag

        # Kernel page in kernel mode
        if k_flag:
            return r << 2 | w << 1 | int(x), 0

        # User page in kernel mode
        else:
            if not self.Sum:
                r = w = x = False
            return 0, r << 2 | w << 1 | int(x)

class RISCVSV32(RISCVTranslator):
    def __init__(
        self, 
        table_address:int, 
        elf_dump: ELFDump, 
        Sum:bool, 
        mxr:bool, 
        ignored_pages:list[int] = []
    ) -> None:
        self.unpack_format = "<I"
        self.total_levels = 2
        self.prefix = 0x0
        self.table_sizes = [0x1000, 0x1000]
        self.shifts = [22, 12]
        self.wordsize = 4
        self.ignored_pages = ignored_pages

        super(RISCVSV32, self).__init__(table_address, elf_dump, Sum, mxr)

    def _read_entry(self, index:int, entry:int, level:int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, [[]], 0, 0

        else:
            kernel = not bool(entry & 0x10)
            read = bool(entry & 0x2)
            write = bool(entry & 0x4)
            execute = bool(entry & 0x8)
            permissions_flags = [[kernel, read, write, execute]]

            address = ((entry >> 10) & ((1 << 22) - 1)) << 12
            # Leaf
            if read or write or execute or level == 1:
                return True, permissions_flags, address, 1 << self.shifts[level]
            else:
                # Upper tables pointers
                return True, permissions_flags, address, 0

class RISCVSV39(RISCVTranslator):
    def __init__(
        self, 
        table_address: int, 
        elf_dump: ELFDump, 
        Sum: bool, 
        mxr: bool, 
        ignored_pages: list[int] = []
    ) -> None:
        self.unpack_format = "<Q"
        self.total_levels = 3
        self.prefix = 0x0
        self.table_sizes = [0x1000, 0x1000, 0x1000]
        self.shifts = [30, 21, 12]
        self.wordsize = 8
        self.ignored_pages = ignored_pages

        super(RISCVSV39, self).__init__(table_address, elf_dump, Sum, mxr)

    def _read_entry(self, index: int, entry: int, level: int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, [[]], 0, 0

        else:
            kernel = not bool(entry & 0x10)
            read = bool(entry & 0x2)
            write = bool(entry & 0x4)
            execute = bool(entry & 0x8)
            permissions_flags = [[kernel, read, write, execute]]

            address = ((entry >> 10) & ((1 << 44) - 1)) << 12
            # Leaf
            if read or write or execute or level == 2:
                return True, permissions_flags, address, 1 << self.shifts[level]
            else:
                # Upper tables pointers
                return True, permissions_flags, address, 0

#########
# ARM   #
#########
class ARMTranslator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(mmu_class:type, registers:dict[str, int], ignored_pages:list[int]) -> dict[str, int|bool|list[int]]:
        if mmu_class is ARMShort:
            dtb = ((registers['ttbr1']      >> 14) & ((1 << 18) - 1)) << 14
            ee = bool((registers['sctlr']   >> 25) & 0x1)
            afe = bool(((registers['sctlr'] >> 29) & 0x1))
        else:
            raise NotImplementedError

        return {
            'table_address': dtb,
            'ee': ee,
            'afe': afe,
            'ignored_pages': ignored_pages
        }

    @staticmethod
    def derive_translator_class(registers:dict[str, int]) -> type:
        eae = registers['ttbcr'] & 0x80000000

        if not eae:
            return ARMShort
        else:
            raise NotImplementedError

    @staticmethod
    def normalize_registers(registers:dict[str, int]) -> dict[str, int]:
        # QEMU exports TTBR0/1/TTBCR/SCTLR with different names (SUPPOSING NO SECURE MEMORY)
        ttbr0 = 0
        for reg_name in ['TTBR0', 'TTBR0_S', 'TTBR0_EL1', 'TTBR0_EL1_S']:
            if registers.get(reg_name, ''):
                ttbr0 = registers[reg_name]
                break

        ttbr1 = 0
        for reg_name in ['TTBR1', 'TTBR1_S', 'TTBR1_EL1', 'TTBR1_EL1_S']:
            if registers.get(reg_name, ''):
                ttbr1 = registers[reg_name]
                break

        ttbcr = 0
        for reg_name in ['TTBCR', 'TTBCR_S', 'TCR_EL1', 'TCR_EL3']:
            if registers.get(reg_name, ''):
                ttbcr = registers[reg_name]
                break
        registers['ttbcr'] = ttbcr

        sctlr = 0
        for reg_name in ['SCTLR', 'SCTLR_S']:
            if registers.get(reg_name, ''):
                ttbcr = registers[reg_name]
                break
        registers['sctlr'] = sctlr

        # If TTBCR.N is 0 use TTBR0 as TTBR1
        registers['ttbr0'] = ttbr0
        registers['ttbr1'] = ttbr1 if (registers['ttbcr'] & 0x7) else ttbr0
        return registers

    def __init__(self, table_address:int, elf_dump:ELFDump, ee:bool = False, afe:bool = False):
        super(ARMTranslator, self).__init__(table_address, elf_dump)

        print('Creating resolution trees...')
        self._reconstruct_mappings(self.table_address, user_permissions_mask=[[True, True, True, True, True, True]])

    def _finalize_virtual_address(self, virtual_address:int) -> int:
        return virtual_address

    def _reconstruct_permissions(self, permissions_mask:list[list[bool]]) -> tuple[int, int]:
        kr_flags, kw_flags, kx_flags, ur_flags, uw_flags, ux_flags = zip(*permissions_mask) # Partially hierarchical

        kr = kr_flags[-1]
        kw = kw_flags[-1]
        kx = all(kx_flags)
        ur = ur_flags[-1]
        uw = uw_flags[-1]
        ux = ux_flags[-1] and ur

        return kr << 2 | kw << 1 | int(kx), ur << 2 | uw << 1 | int(ux)

class ARMShort(ARMTranslator):
    # TODO: at moment it ignores domains
    # relevant to XN and PXN

    def __init__(
        self, 
        table_address: int, 
        elf_dump: ELFDump, 
        ee: bool, 
        afe: bool, 
        ignored_pages: list[int] = []
    ) -> None:
        self.unpack_format = ">I" if ee else "<I"
        self.total_levels = 2
        self.prefix = 0x0
        self.table_sizes = [0x4000, 0x400]
        self.shifts = [20, 12]
        self.ee = ee
        self.afe = afe
        self.wordsize = 4
        self.minimum_page = 0x1000
        self.ignored_pages = ignored_pages

        super(ARMShort, self).__init__(table_address, elf_dump, ee, afe)

    def _return_short_permissions_mask(self, access_permission:int, kernel_execute:bool, user_execute:bool) -> list[list[bool]]:
        if self.afe: # AP[2:1] mode
            if access_permission == 0:
                return [[True, True, kernel_execute, False, False, user_execute]]
            elif access_permission == 1:
                return [[True, True, kernel_execute, True, True, user_execute]]
            elif access_permission == 2:
                return [[True, False, kernel_execute, False, False, user_execute]]
            else:
                return [[True, False, kernel_execute, True, False, user_execute]]

        else: # AP[2:0] mode
            if access_permission == 0 or access_permission == 4:
                return [[False, False, kernel_execute, False, False, user_execute]]
            elif access_permission == 1:
                return [[True, True, kernel_execute, False, False, user_execute]]
            elif access_permission == 2:
                return [[True, True, kernel_execute, True, False, user_execute]]
            elif access_permission == 3:
                return [[True, True, kernel_execute, True, True, user_execute]]
            elif access_permission == 5:
                return [[True, False, kernel_execute, False, False, user_execute]]
            else:
                return [[True, False, kernel_execute, True, False, user_execute]]

    def _read_entry(self, index:int, entry:int, level:int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)
        table_flag = entry & 0x3

        # Empty entry
        if table_flag == 0:
            return False, [[]], 0, 0

        if level == 0:
            # Upper tables pointers
            if table_flag == 1:
                address = ((entry >> 10) & ((1 << 22) - 1)) << 10
                permissions_flags = [[True, True, not bool(entry & 0x4), True, True, True]]
                return True, permissions_flags, address, 0

            # Leaves
            else:
                kernel_execute = not bool(entry & 0x1)
                user_execute = not bool(entry & 0x10)
                access_permission = (((entry >> 15) & 0x1) << 2) | ((entry >> 10) & 0x3)
                permissions_flags = self._return_short_permissions_mask(access_permission, kernel_execute, user_execute)

                if not ((entry >> 18) & 0x1): # Section
                    address = ((entry >> 20) & ((1 << 12) - 1)) << 20
                    offset_size = 20
                else: # Supersection
                    # Super Section entries are repeated 16 times, use only the first one
                    if index % 16 != 0:
                        return False, [[]], 0, 0
                    address = (((entry >> 5) & ((1 << 4) - 1)) << 36) | (((entry >> 20) & ((1 << 4) - 1)) << 32) | ((entry >> 24) & ((1 << 8) - 1)) << 24
                    offset_size = 24
                return True, permissions_flags, address, 1 << offset_size

        else:

            # Large page
            if table_flag == 1:
                # Large pages entries are repeated 16 times, use only the first one
                if index % 16 != 0:
                    return False, [[]], 0, 0
                user_execute = not bool(entry & 0x8000)
                address = ((entry >> 16) & ((1 << 16) - 1)) << 16
                offset_size = 16

            # Small page
            else:
                address = ((entry >> 12) & ((1 << 20) - 1)) << 12
                user_execute = not bool(entry & 0x1)
                offset_size = 12

            access_permission = (((entry >> 9) & 0x1) << 2) | ((entry >> 4) & 0x3)
            permissions_flags = self._return_short_permissions_mask(access_permission, True, user_execute)
            return True, permissions_flags, address, 1 << offset_size

#############
# Aarch64   #
#############
class AArch64Translator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(translator_class:type, registers:dict[str,int], ignored_pages:list[int]) -> dict[str,int|bool|list[int]]:
        # We ignore PSTATE.PAN, PSTATE.UAO

        if translator_class is AArch64Long:
            tcr = registers['tcr_el1']
            tg1 =  (tcr >> 30) & 0x3
            tree_size = (tcr >> 16) & 0x3F
            tree_size = max(tree_size, 16) # 21?

            # Determine which part of the top table address is inserted into TTBR1_EL1
            tree_structure = AArch64Long._get_tree_structure(tree_size, tg1)
            steps = AArch64Long._calculate_steps(tree_structure[0], tree_structure[1], tree_size)
            print(steps)
            dtb = ((registers['ttbr1_el1'] >> steps) & ((1 << 47 - steps + 1) - 1)) << steps

            ee = bool((registers['sctlr_el1'] >> 25) & 0x1)
            hpd1 = not bool(((tcr >> 42) & 0x1))
            wxn = bool(((registers['sctlr_el1'] >> 19) & 0x1))
        else:
            raise NotImplementedError

        return {
            'table_address': dtb,
            't1sz': tree_size,
            'tg1': tg1,
            'ee': ee,
            'hpd1': hpd1,
            'wxn': wxn,
            'ignored_pages': ignored_pages
        }

    @staticmethod
    def derive_translator_class(registers:dict[str, int]) -> type:
        # I haven't find a way to distinguisch Long to LongLPA modes...
        return AArch64Long

    @staticmethod
    def normalize_registers(registers:dict[str, int]) -> dict[str, int]:
        # QEMU exports TTBR0_EL1/TTBR1_EL1/TCR_EL1/SCTLR_EL1 with different names (SUPPOSING NO SECURE MEMORY)
        ttbr0 = 0
        for register_name in ['TTBR0_EL1', 'TTBR0_EL1_S']:
            if registers.get(register_name, ''):
                ttbr0 = int(registers[register_name])
                break

        ttbr1 = 0
        for register_name in ['TTBR1_EL1', 'TTBR1_EL1_S']:
            if registers.get(register_name, ''):
                ttbr1 = int(registers[register_name])
                break

        tcr = 0
        for register_name in ['TCR_EL1', 'TCR_EL1_S']:
            if registers.get(register_name, ''):
                tcr = int(registers[register_name])
                break
        registers['tcr_el1'] = tcr

        sctlr = 0
        for register_name in ['SCTLR', 'SCTLR_S']:
            if registers.get(register_name, ''):
                sctlr = int(registers[register_name])
                break
        registers['sctlr_el1'] = sctlr

        registers['ttbr0_el1'] = ttbr0
        registers['ttbr1_el1'] = ttbr1 if ttbr1 else ttbr0
        return registers

    def __init__(
        self, 
        dtb:int, 
        elf_dump:ELFDump, 
        t1sz:int, 
        tg1:int, 
        ee:bool = False, 
        hpd1:bool = False, 
        wxn:bool = False
    ) -> None:
        super(AArch64Translator, self).__init__(dtb, elf_dump)
        print('Creating resolution trees...')
        self.hpd1 = hpd1
        self.wxn = wxn
        self._reconstruct_mappings(self.table_address, user_permissions_mask=[[True, True, True, True, True, True]])

    def _finalize_virtual_address(self) -> None:
        raise NotImplementedError

    def _reconstruct_permissions(self, permissions_mask:list[list[bool]]) -> tuple[int, int]:
        kr_flags, kw_flags, kx_flags, ur_flags, uw_flags, ux_flags = zip(*permissions_mask)

        # No hierarchical permissions
        if self.hpd1:
            kx = (kw_flags[-1] ^ kx_flags[-1]) and kx_flags[-1] and (not uw_flags[-1]) if self.wxn else kx_flags[-1]
            ux = (uw_flags[-1] ^ ux_flags[-1]) and ux_flags[-1] if self.wxn else ux_flags[-1]

            return kr_flags[-1] << 2 | kw_flags[-1] << 1 | int(kx), ur_flags[-1] << 2 | uw_flags[-1] << 1 | int(ux)

        # Full hierarchical
        else:
            kr = all(kr_flags)
            kw = all(kw_flags)
            kx = all(kx_flags)
            ur = all(ur_flags)
            uw = all(uw_flags)
            ux = all(ux_flags)
            kx = (kw ^ kx) and kx and (not uw) if self.wxn else kx
            ux = (uw ^ ux) and ux if self.wxn else ux
            return kr << 2 | kw << 1 | int(kx), ur << 2 | uw << 1 | int(ux)

    def _return_pmask(self, ap:int, kx:bool, ux:bool) -> list[list[bool]]:
        if ap == 0:
            return [[True, True, kx, False, False, ux]]
        elif ap == 1:
            return [[True, True, kx, True, True, ux]]
        elif ap == 2:
            return [[True, False, kx, False, False, ux]]
        else:
            return [[True, False, kx, True, False, ux]]

    def _return_pmask_aptable(self, ap:int, kx:bool, ux:bool) -> list[list[bool]]:
        if ap == 0:
            return [[True, True, kx, True, True, ux]]
        elif ap == 1:
            return [[True, True, kx, False, False, ux]]
        elif ap == 2:
            return [[True, False, kx, True, False, ux]]
        else:
            return [[True, False, kx, False, False, ux]]

class AArch64Long(AArch64Translator):
    @staticmethod
    def _get_tree_structure(tree_size:int, tree_granularity_index:int) -> tuple[int, int, int]:
        if tree_granularity_index == 1:
            granularity = 16384
        elif tree_granularity_index == 2:
            granularity = 4096
        elif tree_granularity_index == 3:
            granularity = 65536
        else:
            raise ValueError

        if granularity == 4096:
            if 12 <= tree_size <= 24:
                t = (0, 1 << (28 - tree_size))
            elif 25 <= tree_size <= 33:
                t = (1, 1 << (37 - tree_size))
            elif 34 <= tree_size <= 42:
                t = (2, 1 << (46 - tree_size))
            else:
                t = (3, 1 << (55 - tree_size))
        elif granularity == 16384:
            if tree_size == 16:
                t = (0, 16)
            elif 17 <= tree_size <= 27:
                t = (1, 1 << (31 - tree_size))
            elif 28 <= tree_size <= 38:
                t = (2, 1 << (42 - tree_size))
            else:
                t = (3, 1 << (53 - tree_size))
        elif granularity == 65536:
            if 12 <= tree_size <= 21:
                t = (1, 1 << (25 - tree_size))
            elif 22 <= tree_size <= 34:
                t = (2, 1 << (38 - tree_size))
            else:
                t = (3, 1 << (51 - tree_size))
        else:
            raise ValueError

        return (granularity, 4 - t[0], t[1]) # (granule, levels, top_table_size)

    @staticmethod
    def _calculate_steps(granularity:int, levels:int, tree_size:int) -> int:
        print(granularity, levels, tree_size)
        if granularity == 4096:
            step = 9
            max_value = 55
        elif granularity == 16384:
            step = 11
            max_value = 53
        else:
            step = 13
            max_value = 51
        return (max_value - (levels - 1) * step) - tree_size

    def __init__(
        self, 
        table_address:int, 
        elf_dump:ELFDump, 
        t1sz:int, 
        tg1:int, 
        ee:bool, 
        hpd1:bool, 
        wxn:bool, 
        ignored_pages:list[int] = []
    ) -> None:

        self.unpack_format = ">Q" if ee else "<Q"
        tree_structure = AArch64Long._get_tree_structure(t1sz, tg1)

        self.total_levels = tree_structure[1]
        self.prefix = (1 << 64) - (1 << (64 - t1sz))
        granule, levels, top_size = tree_structure
        self.table_sizes = [
            top_size if level == 0 
            else granule 
            for level in range(levels)
        ]
        if granule == 0x1000:
            self.shifts = [x for x in [39, 30, 21, 12][4-levels:]]
        elif granule == 0x4000:
            self.shifts = [x for x in [47, 36, 25, 14][4-levels:]]
        else:
            self.shifts = [x for x in [42, 29, 16][3-levels:]]

        self.wordsize = 8
        self.t1sz = t1sz
        self.tg1 = tg1
        self.ee = ee
        self.hpd1 = hpd1
        self.wxn = wxn
        self.granule = tree_structure[0]
        self.minimum_page = self.granule
        self.ignored_pages = ignored_pages
        
        super(AArch64Long, self).__init__(table_address, elf_dump, t1sz, tg1, ee, hpd1, wxn)

    def _read_entry(self, index:int, entry:int, level:int) -> tuple[bool, list[list[bool]], int, int]:
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, [[]], 0, 0

        # First levels
        if (level + 1 < self.total_levels):
            # Block entry
            if (entry & 0x3) == 1:
                if self.granule == 0x1000:
                    if level == 0:
                        shifting = 30
                    else:
                        shifting = 21
                elif self.granule == 0x4000:
                    shifting = 25
                else:
                    shifting = 29

                address = ((entry >> shifting) & ((1 << 47 - shifting + 1) - 1)) << shifting
                access_permission = (entry >> 6) & 0x3
                kernel_execute = not bool((entry >> 53) & 0x1)
                user_execute = not bool((entry >> 54) & 0x1)
                permissions_mask = self._return_pmask(access_permission, kernel_execute, user_execute)
                return True, permissions_mask, address, 1 << shifting

            # Page table pointer
            else:
                if self.granule == 0x1000:
                    m = 12
                elif self.granule == 0x4000:
                    m = 14
                else:
                    m = 16
                address = ((entry >> m) & ((1 << 47 - m + 1) - 1)) << m
                access_permission = (entry >> 61) & 0x3
                kernel_execute = not bool((entry >> 59) & 0x1)
                user_execute = not bool((entry >> 60) & 0x1)
                permissions_mask = self._return_pmask_aptable(access_permission, kernel_execute, user_execute)
                return True, permissions_mask, address, 0

        else:
            # Reserved entry:
            if entry & 0x3 == 1:
                return False, [[]], 0, 0

            # Page
            else:
                if self.granule == 0x1000:
                    address = ((entry >> 12) & ((1 << 36) - 1)) << 12
                    shifting = 12
                elif self.granule == 0x4000:
                    address = ((entry >> 14) & ((1 << 34) - 1)) << 14
                    shifting = 14
                else:
                    address = (((entry >> 12) & 0xF) << 48) | (((entry >> 16) & ((1 << 32) - 1)) << 16)
                    shifting = 16

                access_permission = (entry >> 6) & 0x3
                kernel_execute = not bool((entry >> 53) & 0x1)
                user_execute = not bool((entry >> 54) & 0x1)
                permissions_mask = self._return_pmask(access_permission, kernel_execute, user_execute)
                return True, permissions_mask, address, 1 << shifting

    def _finalize_virtual_address(self, virtual_address, permissions):
        return self.prefix | virtual_address

##################
# Class Selector #
##################
def factory(translator: type, elf_dump: ELFDump, ignored_pages: list[int]) -> AArch64Long|ARMShort|RISCVSV32|RISCVSV39|IntelAMD64|IntelIA32|IntelPAE:
    machine_data:dict[str, Any] = elf_dump.get_machine_data()
    registers:dict[str, int] = machine_data['CPURegisters']
    
    if translator == type(IntelTranslator):
        max_physical_address = machine_data['CPUSpecifics']['MAXPHYADDR']
        if type(max_physical_address) == str and '[D' in max_physical_address:
            max_physical_address = int(max_physical_address[:-2])
        assert isinstance(max_physical_address, int)
        translator_class = IntelTranslator.derive_translator_class(registers)
        mmu_settings = IntelTranslator.derive_mmu_settings(translator_class, registers, max_physical_address, ignored_pages)
    elif translator == type(RISCVTranslator):
        translator_class = RISCVTranslator.derive_translator_class(registers)
        mmu_settings = RISCVTranslator.derive_mmu_settings(translator_class, registers, ignored_pages)
    elif translator == type(ARMTranslator):
        registers = ARMTranslator.normalize_registers(registers)
        translator_class = ARMTranslator.derive_translator_class(registers)
        mmu_settings = ARMTranslator.derive_mmu_settings(translator_class, registers, ignored_pages)
    elif translator == type(AArch64Translator):
        registers = AArch64Translator.normalize_registers(registers)
        translator_class = AArch64Translator.derive_translator_class(registers)
        mmu_settings = AArch64Translator.derive_mmu_settings(translator_class, registers, ignored_pages)
    else:
        raise Exception('Unknown architecture')
    return translator_class(elf_dump = elf_dump, **mmu_settings)

def get_virtual_space(elf_dump:ELFDump, ignored_pages:list[int]) -> AArch64Long|ARMShort|RISCVSV32|RISCVSV39|IntelAMD64|IntelIA32|IntelPAE:
    """
    Returns a virtual_space from a physical one
    """
    architecture = elf_dump.get_machine_data()['Architecture']
    assert isinstance(architecture, str)
    architecture = architecture.lower()

    if 'aarch64' in architecture:
        return factory(type(AArch64Translator),   elf_dump, ignored_pages)
    elif 'arm' in architecture:
        return factory(type(ARMTranslator),       elf_dump, ignored_pages)
    elif 'riscv' in architecture:
        return factory(type(RISCVTranslator),     elf_dump, ignored_pages)
    elif 'x86' in architecture or '386' in architecture:
        return factory(type(IntelTranslator),     elf_dump, ignored_pages)
    else:
        raise Exception('Unknown architecture')
