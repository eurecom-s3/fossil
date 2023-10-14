from typing import DefaultDict
import numpy as np
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment
import json
import os
import subprocess
from string import ascii_uppercase, ascii_lowercase, digits
import random
from collections import defaultdict, Counter
from struct import iter_unpack
from bitarray import bitarray
from tqdm import tqdm
from bisect import bisect
from mmap import mmap, PROT_READ
import logging
import ipaddress
from scapy.all import IP, TCP, UDP, ICMP, Ether
import binascii

class IMSimple:
    """Fast search in intervals (begin) (end)"""
    def __init__(self, keys, values):
        self.keys = keys
        self.values = values

    def __getitem__(self, x):
        idx = bisect(self.keys, x) - 1
        begin = self.keys[idx]
        if begin <= x < self.values[idx]:
            return x - begin
        else:
            return -1

    def contains(self, x, size):
        idx = bisect(self.keys, x) - 1
        begin = self.keys[idx]
        end = self.values[idx]
        if not(begin <= x < end) or x + size >= end:
            return -1
        else:
            return x - begin

    def get_values(self):
        return zip(self.keys, self.values)

    def get_extremes(self):
        return self.keys[0], self.values[-1]

class IMData:
    """Fast search in intervals (begin), (end, associated data)"""
    def __init__(self, keys, values):
        self.keys = keys
        self.values = values

    def __getitem__(self, x):
        idx = bisect(self.keys, x) - 1
        begin = self.keys[idx]
        end, data = self.values[idx]
        if begin <= x < end:
            return data
        else:
            return -1

    def contains(self, x, size):
        idx = bisect(self.keys, x) - 1
        begin = self.keys[idx]
        end, data = self.values[idx]
        if not(begin <= x < end) or x + size >= end:
            return -1
        else:
            return data

    def get_values(self):
        return zip(self.keys, self.values)

    def get_extremes(self):
        return self.keys[0], self.values[-1][0]

class IMOffsets:
    """Fast search in intervals (begin), (end, associated offset)"""
    def __init__(self, keys, values):
        self.keys = keys
        self.values = values

    def __getitem__(self, x):
        idx = bisect(self.keys, x) - 1
        begin = self.keys[idx]
        end, data = self.values[idx]
        if begin <= x < end:
            return x - begin + data
        else:
            return -1

    def contains(self, x, size):
        """Return the maximum size and the list of intervals"""
        idx = bisect(self.keys, x) - 1
        begin = self.keys[idx]
        end, data = self.values[idx]
        if not(begin <= x < end):
            return 0, []

        intervals = [(x, min(end - x, size), x - begin + data)]
        if end - x >= size:
            return size, intervals

        # The address space requested is bigger than a single interval
        start = end
        remaining = size - (end - x)
        idx += 1
        print(start, remaining, idx)
        while idx < len(self.values):
            begin = self.keys[idx]
            end, data = self.values[idx]
            
            # Virtual addresses must be contigous
            if begin != start:
                return size - remaining, intervals
            
            interval_size = min(end - begin, remaining)
            intervals.append((start, interval_size, data))
            remaining -= interval_size
            if not remaining:
                return size, intervals
            start += interval_size
            idx += 1

    def get_values(self):
        return zip(self.keys, self.values)

    def get_extremes(self):
        return self.keys[0], self.values[-1][0]


class IMOverlapping: 
    """Fast search in overlapping intervals (begin), (end, [associated
    offsets])"""

    def __init__(self, intervals):
        limit2changes = defaultdict(lambda: ([], []))
        for idx, (l, r, v) in enumerate(intervals):
            assert l < r
            limit2changes[l][0].append(v)
            limit2changes[r][1].append(v)
        self.limits, changes = zip(*sorted(limit2changes.items()))
        
        self.results = [[]]        
        s = set()
        offsets = {}
        res = []
        for idx, (arrivals, departures) in enumerate(changes):
            
            s.difference_update(departures)
            for i in departures:
                offsets.pop(i)
            
            for i in s:
                offsets[i] += (self.limits[idx] - self.limits[idx - 1]) 
            
            s.update(arrivals)
            for i in arrivals:
                offsets[i] = 0
            
            res.clear()
            for k,v in offsets.items():
                res.extend([i + v for i in k])
            self.results.append(res.copy())
        
    def __getitem__(self, x):
        idx = bisect(self.limits, x)
        k = x - self.limits[idx - 1]
        return [k + p for p in self.results[idx]]

    def get_values(self):
        return zip(self.limits, self.results)


class ELFDump:
    def __init__(self, elf_filename):
        self.filename = elf_filename
        self.machine_data = {}
        self.p2o = None   # Physical to RAM (ELF offset)
        self.o2p = None   # RAM (ELF offset) to Physical
        self.p2mmd = None # Physical to Memory Mapped Devices (ELF offset)
        self.elf_buf = np.zeros(0, dtype=np.byte)
        self.elf_filename = elf_filename
        
        with open(self.elf_filename, "rb") as elf_fd:

            # Load the ELF in memory
            self.elf_buf = np.fromfile(elf_fd, dtype=np.byte)
            elf_fd.seek(0)

            # Parse the ELF file
            self.__read_elf_file(elf_fd)

    def __read_elf_file(self, elf_fd):
        """Parse the dump in ELF format"""
        o2p_list = []
        p2o_list = []
        p2mmd_list = []
        elf_file = ELFFile(elf_fd)

        for segm in elf_file.iter_segments():

            # NOTES
            if isinstance(segm, NoteSegment):
                for note in segm.iter_notes():

                    # Ignore NOTE genrated by other softwares
                    if note["n_name"] != "FOSSIL":
                        continue

                    # At moment only one type of note
                    if note["n_type"] != 0xdeadc0de:
                        continue

                    # Suppose only one deadcode note
                    self.machine_data = json.loads(note["n_desc"].rstrip(b"\x00"))
                    self.machine_data["Endianness"] = "little" if elf_file.header["e_ident"].EI_DATA == "ELFDATA2LSB" else "big"
                    self.machine_data["Architecture"] = "_".join(elf_file.header["e_machine"].split("_")[1:])
            else:
                # Fill arrays needed to translate physical addresses to file offsets
                r_start = segm["p_vaddr"]
                r_end = r_start + segm["p_memsz"]

                if segm["p_filesz"]:
                    p_offset = segm["p_offset"]
                    p2o_list.append((r_start, (r_end, p_offset)))
                    o2p_list.append((p_offset, (p_offset + (r_end - r_start), r_start)))
                else:
                    # device_name = "" # UNUSED
                    for device in self.machine_data["MemoryMappedDevices"]: # Possible because NOTES always the first segment
                        if device[0] == r_start:
                            # device_name = device[1] # UNUSED
                            break
                    p2mmd_list.append((r_start, r_end))
        
        # Debug
        # self.p2o_list = p2o_list
        # self.o2p_list = o2p_list
        # self.p2mmd_list = p2mmd_list

        # Compact intervals
        p2o_list = self._compact_intervals(p2o_list)
        o2p_list = self._compact_intervals(o2p_list)
        p2mmd_list = self._compact_intervals_simple(p2mmd_list)

        self.p2o = IMOffsets(*list(zip(*sorted(p2o_list))))
        self.o2p = IMOffsets(*list(zip(*sorted(o2p_list))))
        self.p2mmd = IMSimple(*list(zip(*sorted(p2mmd_list))))
    
    def _compact_intervals_simple(self, intervals):
        """Compact intervals if pointer values are contiguos"""
        fused_intervals = []
        prev_begin = prev_end = -1
        for interval in intervals:
            begin, end = interval            
            if prev_end == begin:
                prev_end = end
            else:
                fused_intervals.append((prev_begin, prev_end))
                prev_begin = begin
                prev_end = end
        
        if prev_begin != begin:
            fused_intervals.append((prev_begin, prev_end))
        else:
            fused_intervals.append((begin, end))

        return fused_intervals[1:]

    def _compact_intervals(self, intervals):
        """Compact intervals if pointer and pointed values are contigous"""
        fused_intervals = []
        prev_begin = prev_end = prev_phy = -1
        for interval in intervals:
            begin, (end, phy) = interval            
            if prev_end == begin and prev_phy + (prev_end - prev_begin) == phy:
                prev_end = end
            else:
                fused_intervals.append((prev_begin, (prev_end, prev_phy)))
                prev_begin = begin
                prev_end = end
                prev_phy = phy
        
        if prev_begin != begin:
            fused_intervals.append((prev_begin, (prev_end, prev_phy)))
        else:
            fused_intervals.append((begin, (end, phy)))

        return fused_intervals[1:]
    
    def in_ram(self, paddr, size=1):
        """Return True if the interval is completely in RAM"""
        return self.p2o.contains(paddr, size)[0] == size

    def in_mmd(self, paddr, size=1):
        """Return True if the interval is completely in Memory mapped devices space"""
        return True if self.p2mmd.contains(paddr, size) != -1 else False

    def get_data(self, paddr, size):
        """Return the data at physical address (interval)"""
        size_available, intervals = self.p2o.contains(paddr, size)
        if size_available != size:
            return bytes()
        
        ret = bytearray()
        for interval in intervals:
            _, interval_size, offset = interval
            ret.extend(self.elf_buf[offset:offset+interval_size].tobytes())

        return ret
    
    def get_data_raw(self, offset, size=1):
        """Return the data at the offset in the ELF (interval)"""
        return self.elf_buf[offset:offset+size].tobytes()

    def get_machine_data(self):
        """Return a dict containing machine configuration"""
        return self.machine_data

    def get_ram_regions(self):
        """Return all the RAM regions of the machine and the associated offset"""
        return self.p2o.get_values()

    def get_mmd_regions(self):
        """Return all the Memory mapped devices intervals of the machine and the associated offset"""
        return self.p2mmd.get_values()

    def retrieve_strings_offsets(self, min_len=3):
        # Generate random separator
        separator = ''.join(random.choice(ascii_lowercase + ascii_uppercase + digits) for _ in range(10))

        # Use the external program `strings` which is order of magnitude more
        # fast (collect also UTF-16)!
        elf_path = os.path.realpath(self.elf_filename)
        strings_proc = subprocess.Popen(["strings", "-a", "-n", f"{min_len}", "-t", "x", "-w", "-s", separator, f"{elf_path}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        strings_out, strings_stderr = strings_proc.communicate()
        if strings_proc.returncode:
            print(strings_stderr)
            raise OSError

        strings_proc = subprocess.Popen(["strings", "-a", "-e", "l" if self.machine_data["Endianness"] == "little" else "b", "-n", f"{min_len}", "-t", "x", "-w", "-s", separator, f"{elf_path}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        strings_out_utf16, strings_stderr = strings_proc.communicate()
        if strings_proc.returncode:
            print(strings_stderr)
            raise OSError

        strings_out = strings_out + " " + strings_out_utf16

        # Translate file offset in physical addresses (ignoring ELF internal strings)
        strings_offsets = []
        for string in strings_out.split(separator):

            try:
                p_offset, value = string.lstrip().split(maxsplit=1)
                p_offset = int(p_offset, 16)
            except: # Ignore not valid lines
                continue

            # Allow only NULL-terminated strings
            try:
                if self.elf_buf[p_offset + len(value)] != 0:
                    continue
            except: # End of File
                pass

            if self.o2p[p_offset] == -1:
                continue

            strings_offsets.append((value, p_offset))

        return strings_offsets

def get_virtspace(phy, ignored_pages):
    """Return a virtspace from a physical one"""
    architecture = phy.get_machine_data()["Architecture"].lower()
    if "aarch64" in architecture:
        return AArch64Translator.factory(phy, ignored_pages)
    elif "arm" in architecture:
        return ARMTranslator.factory(phy, ignored_pages)
    elif "riscv" in architecture:
        return RISCVTranslator.factory(phy, ignored_pages)
    elif "x86" in architecture or "386" in architecture:
        return IntelTranslator.factory(phy, ignored_pages)
    else:
        raise Exception("Unknown architecture")

class AddressTranslator:
    def __init__(self, dtb, phy):
        self.dtb = dtb
        self.phy = phy

        # Set machine specifics
        if self.wordsize == 4:
            self.word_type = np.uint32
            if self.phy.machine_data["Endianness"] == "big":
                self.word_fmt = np.dtype(">u4")
            else:
                self.word_fmt = np.dtype("<u4")
        else:
            self.word_type = np.uint64
            if self.phy.machine_data["Endianness"] == "big":
                self.word_fmt = np.dtype(">u8")
            else:
                self.word_fmt = np.dtype("<u8")
        
        self.v2o = None
        self.o2v = None
        self.pmasks = None
        #self.minimum_page = 0

    def _read_entry(self, idx, entry, lvl):
        """Decode radix tree entry"""
        raise NotImplementedError

    def _reconstruct_permissions(self, pmask):
        """Reconstruct permission masks from radix tree entry"""
        raise NotImplementedError

    def _finalize_virt_addr(self, virt_addr, permissions):
        """Apply architecture specific virtual address modifications"""
        raise NotImplementedError
    
    def get_data_virt(self, vaddr, size=1):
        """Return data starting from a virtual address"""
        size_available, intervals = self.v2o.contains(vaddr, size)
        if size_available != size:
            return bytes()
        
        ret = bytearray()
        for interval in intervals:
            _, interval_size, offset = interval
            ret.extend(self.elf_buf[offset:offset+interval_size].tobytes())

        return ret
        
    def get_data_phy(self, paddr, size):
        """Return data starting from a physical address"""
        return self.phy.get_data(paddr, size)
    
    def get_data_raw(self, offset, size):
        """Return data starting from an ELF offset"""
        return self.phy.get_data_raw(offset, size)

    def _explore_radixtree(self, table_addr, mapping, reverse_mapping, lvl=0, prefix=0, upmask=list(), stats=None):
        """Explore the radix tree returning virtual <-> physical mappings"""
        i = "\t" * lvl
        logging.debug(f"{i}{hex(table_addr)} {lvl}/{self.total_levels - 1}")
        table = self.phy.get_data(table_addr, self.table_sizes[lvl])

        if not table:
            print(f"Table {hex(table_addr)} size:{self.table_sizes[lvl]} at level {lvl} not in RAM")
            return

        # Ignore physical pages used as placeholders
        if table_addr in self.ignored_pages and lvl == self.total_levels - 1:
            logging.debug(f"Ignoring {hex(table_addr)}")
            return

        for index, entry in enumerate(iter_unpack(self.unpack_fmt, table)):
            is_valid, pmask, phy_addr, page_size = self._read_entry(index, entry[0], lvl)

            if not is_valid:
                continue

            # Statistics
            stats[phy_addr] += 1

            virt_addr = prefix | (index << self.shifts[lvl])
            pmask = upmask + pmask

            if (lvl == self.total_levels - 1) or page_size: # Last radix level or Leaf
                # Ignore pages not in RAM (some OSs map more RAM than available) and not memory mapped devices
                in_ram = self.phy.in_ram(phy_addr, page_size)
                in_mmd = self.phy.in_mmd(phy_addr, page_size)
                if not in_ram and not in_mmd:
                    continue

                permissions = self._reconstruct_permissions(pmask)

                virt_addr = self._finalize_virt_addr(virt_addr, permissions)
                mapping[permissions].append((virt_addr, page_size, phy_addr, in_mmd))

                # Add only RAM address to the reverse translation P2V
                if in_ram and not in_mmd:
                    if permissions not in reverse_mapping:
                        reverse_mapping[permissions] = defaultdict(list)
                    reverse_mapping[permissions][(phy_addr, page_size)].append(virt_addr)
            else:
                # Lower level entry
                self._explore_radixtree(phy_addr, mapping, reverse_mapping, lvl=lvl+1, prefix=virt_addr, upmask=pmask, stats=stats)

    def _compact_intervals_virt_offset(self, intervals):
        """Compact intervals if virtual addresses and offsets values are
        contigous (virt -> offset)"""
        fused_intervals = []
        prev_begin = prev_end = prev_offset = -1
        for interval in intervals:
            begin, end, phy, _ = interval

            offset = self.phy.p2o[phy]
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
            offset = self.phy.p2o[phy]
            if offset == -1:
                print(f"ERROR!! {phy}")
            else:
                fused_intervals.append((begin, (end, offset)))
        return fused_intervals[1:]

    def _compact_intervals_permissions(self, intervals):
        """Compact intervals if virtual addresses are contigous and permissions are equals"""
        fused_intervals = []
        prev_begin = prev_end = -1
        prev_pmask = (0, 0)
        for interval in intervals:
            begin, end, _, pmask = interval            
            if prev_end == begin and prev_pmask == pmask:
                prev_end = end
            else:
                fused_intervals.append((prev_begin, (prev_end, prev_pmask)))
                prev_begin = begin
                prev_end = end
                prev_pmask = pmask
        
        if prev_begin != begin:
            fused_intervals.append((prev_begin, (prev_end, prev_pmask)))
        else:
            fused_intervals.append((begin, (end, pmask)))

        return fused_intervals[1:]

    def _reconstruct_mappings(self, table_addr, upmask):
        # Explore the radix tree
        mapping = defaultdict(list)
        reverse_mapping = {}
        stats = DefaultDict(int)
        self._explore_radixtree(table_addr, mapping, reverse_mapping, upmask=upmask, stats=stats)

        # Print statistics
        stats = Counter(stats)
        # for k,v in stats.most_common(10):
        #     print(hex(k), v)

        # Needed for ELF virtual mapping reconstruction
        self.reverse_mapping = reverse_mapping
        self.mapping = mapping

        # Collect all intervals (start, end+1, phy_page, pmask)
        intervals = []
        for pmask, mapping_p in mapping.items():
            if pmask[0] == 0: # or (pmask[0] != 0 and pmask[1] != 0): # Ignore user accessible pages
                continue
            intervals.extend([(x[0], x[0]+x[1], x[2], pmask) for x in mapping_p if not x[3]]) # Ignore MMD
        intervals.sort()

        # Fuse intervals in order to reduce the number of elements to speed up
        fused_intervals_v2o = self._compact_intervals_virt_offset(intervals)
        fused_intervals_permissions = self._compact_intervals_permissions(intervals)
        
        # Offset to virtual is impossible to compact in a easy way due to the
        # multiple-to-one mapping. We order the array and use bisection to find
        # the possible results and a partial 
        intervals_o2v = []
        for pmasks, d in reverse_mapping.items():
            if pmasks[0] == 0: # or (pmask[0] != 0 and pmask[1] != 0): # Ignore user accessible pages
                continue
            for k, v in d.items():
                # We have to translate phy -> offset
                offset = self.phy.p2o[k[0]]
                if offset == -1: # Ignore unresolvable pages
                    continue
                intervals_o2v.append((offset, k[1]+offset, tuple(v)))
        intervals_o2v.sort()

        # Fill resolution objects
        self.v2o = IMOffsets(*list(zip(*fused_intervals_v2o)))
        self.o2v = IMOverlapping(intervals_o2v)
        self.pmasks = IMData(*list(zip(*fused_intervals_permissions)))

    def create_bitmap(self):
        """Create a bitmap starting from the ELF file containing 0 if the byte
        is 0, 1 otherwise"""
        print("Creating bitmap...")
        self.mem_btm = bitarray()
        self.mem_btm.pack(self.phy.elf_buf.tobytes())

    def _find_pointers_align(self, align, null_pages):
        """For a fixed align retrieve all valid pointers in dump"""

        # Workaround for alignment
        aligned_len = self.phy.elf_buf.shape[0] - (self.phy.elf_buf.shape[0] % self.wordsize)
    
        if align == 0:
            end = aligned_len
        else:
            end = aligned_len - (self.wordsize - align)

        # Find all destination addresses which could be valid kernel addresses ignoring too
        # little or too big ones (src -> dst)
        word_array = self.phy.elf_buf[align:end].view(self.word_fmt)
        min_virt, max_virt = self.v2o.get_extremes()
        logging.debug(f"Min virtual address: {hex(min_virt)}, Max virtual address: {hex(max_virt)}") 
        dsts_idx = np.where((word_array >= min_virt) & (word_array <= max_virt))[0]
        dsts = word_array[dsts_idx]
        srcs_offsets = (dsts_idx * self.wordsize) + align # This array contains the offset on the file of the dst candidates (the src of the pointer!)
        ptrs = {}

        for idx, dst in enumerate(tqdm(dsts)):
            # Validate dsts
            dst = int(dst) # All this conversion is due to a numpy "feature" https://github.com/numpy/numpy/issues/5745
            if (dsto := self.v2o[dst]) == -1:
                continue

            # # Heuristic: ignore pointers which point in pages full of zeroes (FP?)
            # if ((dsto >> self.shifts[-1]) << self.shifts[-1]) in null_pages:
            #     continue

            # Validate srcs
            if len(srcs_list := self.o2v[int(srcs_offsets[idx])]) > 0:
                for src in srcs_list:
                    ptrs[src] = dst
        
        return ptrs

    def _find_ip_packets(self, align, ip_addrs):
        """For a fixed align retrieve all IP packet/IP addresses pointers in dump"""

        # Workaround for alignment
        aligned_len = self.phy.elf_buf.shape[0] - (self.phy.elf_buf.shape[0] % 4)
    
        if align == 0:
            end = aligned_len
        else:
            end = aligned_len - (4 - align)

        # Find all possible locations contains a valid IP address/packets
        ip_addrs = [int(ipaddress.IPv4Address(ip)) for ip in ip_addrs]

        # Addresses
        ptrs = []
        fmt = ">u4" if self.phy.machine_data["Endianness"] == "big" else "<u4"
        word_array = self.phy.elf_buf[align:end].view(np.dtype(fmt))
        offsets = (np.argwhere(np.isin(word_array, ip_addrs)).ravel() * 4) + align

        for idx, offset in enumerate(tqdm(offsets)):
            offset = int(offset) # All this conversion is due to a numpy "feature" https://github.com/numpy/numpy/issues/5745
            if ptr := self.o2v[offset]:
                ptrs.append(ptr[0])

        # Packets
        pkts = []
        word_array = self.phy.elf_buf[align:end].view(np.dtype(">u4"))
        offsets = (np.argwhere(np.isin(word_array, ip_addrs)).ravel() * 4) + align # This array contains the offset on the file of the candidates
        
        for idx, offset in enumerate(tqdm(offsets)):
            # Validate dsts
            offset = int(offset)
            if not (ptr := self.o2v[offset-16]):
                continue
                        
            # Evaluate if it is a valid packet or not
            try:
                pkt_buff = self.phy.elf_buf[offset-16:offset+65519].tobytes()
            except Exception as e:
                continue

            # Validate if it is a valid IP packet (src or dest)
            src_pkt = IP(pkt_buff)
            if self._validate_ip_packet(src_pkt):
                src_pkt.remove_payload()
                src_pkt.show2()
                pkts.append(ptr[0])

            dst_pkt = IP(pkt_buff[4:])
            if self._validate_ip_packet(dst_pkt):
                dst_pkt.remove_payload()
                dst_pkt.show2()
                pkts.append(ptr[0])

        return (ptrs, pkts)

    def _find_ethernet_frames(self, align, mac_addrs):
        """For a fixed align retrieve all Ethernet frames/MAC addresses pointers in dump"""

        # Workaround for alignment
        aligned_len = self.phy.elf_buf.shape[0] - (self.phy.elf_buf.shape[0] % 6)
    
        if align == 0:
            end = aligned_len
        else:
            end = aligned_len - (6 - align)

        # Find all possible locations contains a valid IP address/packets
        mac_addrs = [binascii.unhexlify(mac_addr.encode().replace(b':', b'')) for mac_addr in mac_addrs]

        # Addresses
        ptrs = []
        fmt = ">B6" if self.phy.machine_data["Endianness"] == "big" else "<B6"
        word_array = self.phy.elf_buf[align:end].view(np.dtype(fmt))
        offsets = (np.argwhere(np.isin(word_array, mac_addrs)).ravel() * 6) + align

        for offset in enumerate(tqdm(offsets)):
            offset = int(offset) # All this conversion is due to a numpy "feature" https://github.com/numpy/numpy/issues/5745
            if ptr := self.o2v[offset]:
                ptrs.append(ptr[0])

        # Packets
        pkts = []
        word_array = self.phy.elf_buf[align:end].view(np.dtype(">B6"))
        offsets = (np.argwhere(np.isin(word_array, mac_addrs)).ravel() * 6) + align # This array contains the offset on the file of the candidates
        
        for idx, offset in enumerate(tqdm(offsets)):
            # Validate dsts
            offset = int(offset)
            if not (ptr := self.o2v[offset]):
                continue

            try:
                pkt_buff = self.phy.elf_buf[offset-14:offset+1524].tobytes()
            except Exception as e:
                continue

            # Validate if it is a valid Ether packet (src or dest)
            src_pkt = Ether(pkt_buff)
            if self._validate_ethernet_frame(src_pkt):
                # src_pkt.remove_payload()
                # src_pkt.show2()
                pkts.append(ptr[0])

            dst_pkt = Ether(pkt_buff[6:])
            if self._validate_ethernet_frame(dst_pkt):
                # dst_pkt.remove_payload()
                # dst_pkt.show2()
                pkts.append(ptr[0])

        return (ptrs, pkts)

    def _validate_ip_packet(self, pkt):
        if pkt.version != 4 or \
           pkt.ihl * 4 > pkt.len or \
           pkt.proto not in [1, 6, 17] or \
           pkt.options:
           return False

        # TODO: implement checksum check

        return True

    def _validate_ethernet_frame(self, eth_frame):
        return eth_frame.type == 0x0800

    def _find_null_pages(self):
        null_pages = []
        page_size =  1 << self.shifts[-1]
        elf_len =  len(self.phy.elf_buf)
        print("Find null pages...")
        for idx in tqdm(range(0, elf_len, page_size)):
            if not any(self.phy.elf_buf[idx:min(elf_len, idx+page_size)]):
                null_pages.append(idx)
        print(f"Found {len(null_pages)} null pages")
        return set(null_pages)

    def retrieve_pointers(self):
        print("Retrieve pointers...")
        dmap = {}                # virt1 -> virt2        location virt1 point to virt2 one-to-one
        rmap = defaultdict(list) # virt2 -> [virt1, ...] location at virt2 is pointed by [virt1, ...] one-to-many

        # Monothread not super optimized but it's fast :D (thanks Matteo)
        ptrs = {}

        null_pages = {}

        for align in range(self.wordsize):
            print(f"Look for pointers with alignement {align}...")
            p = self._find_pointers_align(align, null_pages)
            print(f"Found {len(p)} new pointers")
            ptrs.update(p)
        # Reconstruct dict
        dmap.update(ptrs)
        for src, dst in ptrs.items():
            rmap[dst].append(src)

        self.ptrs = dmap
        self.rptrs = dict(rmap)

    def retrieve_network_packets(self, ip_addrs, mac_addrs):
        print("Retrieve IP/Ethernet packets...")
        packets = {}
        pkts = []
        ptrs = []
        

        for align in range(4):
            nptrs, npkts = self._find_ip_packets(align, ip_addrs)
            ptrs.extend(nptrs)
            pkts.extend(npkts)

        packets["ip"] = (list(set(ptrs)), list(set(pkts)))

        # for align in range(6):
        #     packets["ethernet"] = self._find_ethernet_frames(align, mac_addrs)        
        
        self.packets = packets

    def retrieve_strings(self, min_len=3, max_symbols_threshold=0.3):
        # Get strings with physical addresses [(string, paddr), ...]
        print("Retrieving strings...")
        strings = {}
        strings_offsets = self.phy.retrieve_strings_offsets(min_len)
        # rw_strings = []

        for string in strings_offsets:
            value, offset = string

            # Ignore strings which are not part of the memory dump (eg, ELF dump constants etc.)
            vaddrs = self.o2v[offset]
            if not vaddrs:
                continue
            
            for vaddr in vaddrs:
                # HEURISTICS if there are more than max_symbol_threshold
                # symbols ignore it
                if sum(not c.isalnum() for c in value)/len(value) >= max_symbols_threshold:
                    continue
                strings[vaddr] = value

                # in_rw = bool(self.pmasks[vaddr][0] & 0x2)
                # if in_rw:
                #     rw_strings.append(vaddr)

                # Add substrings referenced by pointers
                for i in range(1, len(value)):
                    substr_vaddr = i + vaddr
                    if substr_vaddr in self.rptrs:
                        # HEURISTICS if there are more than max_symbol_threshold
                        # symbols percentage ignore it
                        if sum(not c.isalnum() for c in value[i:])/len(value[i:]) >= max_symbols_threshold:
                            continue
                        strings[substr_vaddr] = value[i:]
                        # if in_rw:
                        #     rw_strings.append(substr_vaddr)

        self.strs = strings
        # self.rw_strings = set(rw_strings)

    def export_virtual_memory_elf(self, elf_filename, kernel=True, only_executable=False, ignore_empties=True):
        """Create an ELF file containg the virtual address space of the kernel/process"""
        print("Convert dump to virtual addresses ELF...")
        with open(elf_filename, "wb") as elf_fd:
            # Create the ELF header and write it on the file
            machine_data = self.phy.get_machine_data()
            endianness = machine_data["Endianness"]
            machine = machine_data["Architecture"].lower()

            # Create ELF main header
            if "aarch64" in machine:
                e_machine = 0xB7
            elif "arm" in machine:
                e_machine = 0x28
            elif "riscv" in machine:
                e_machine = 0xF3
            elif "x86_64" in machine:
                e_machine = 0x3E
            elif "386" in machine:
                e_machine = 0x03
            else:
                raise Exception("Unknown architecture")

            e_ehsize = 0x40
            e_phentsize = 0x38
            elf_h = bytearray(e_ehsize)
            elf_h[0x00:0x04] = b'\x7fELF'                                   # Magic
            elf_h[0x04] = 2                                                 # Elf type
            elf_h[0x05] = 1 if endianness == "little" else 2                # Endianness
            elf_h[0x06] = 1                                                 # Version
            elf_h[0x10:0x12] = 0x4.to_bytes(2, endianness)                  # e_type
            elf_h[0x12:0x14] = e_machine.to_bytes(2, endianness)            # e_machine
            elf_h[0x14:0x18] = 0x1.to_bytes(4, endianness)                  # e_version
            elf_h[0x34:0x36] = e_ehsize.to_bytes(2, endianness)             # e_ehsize
            elf_h[0x36:0x38] = e_phentsize.to_bytes(2, endianness)          # e_phentsize
            elf_fd.write(elf_h)

            # For each pmask try to compact intervals in order to reduce the number of segments
            intervals = defaultdict(list)
            for pmasks, intervals_list in self.mapping.items():
                
                if not(bool(pmasks[1]) ^ kernel): # Select only kernel/process mappings
                    continue
                
                if kernel:
                    pmask = pmasks[0]
                else:
                    pmask = pmasks[1]
                
                if only_executable and not(bool(pmask & 0x1)): # Select only/all executable mappings
                    continue
                
                if ignore_empties:
                    for x in intervals_list:
                        if x[3]: # Ignore MMD
                            continue
                        offset = self.v2o[x[0]]
                        if offset == -1:
                            continue
                        if not any(self.phy.elf_buf[offset:offset+x[1]]): # Filter for empty pages
                            continue

                        intervals[pmask].append((x[0], x[0]+x[1], x[2]))
                else:
                    intervals[pmask].extend([(x[0], x[0]+x[1], x[2]) for x in intervals_list if not x[3]]) # Ignore MMD

                intervals[pmask].sort()

                # Compact them
                fused_intervals = []
                prev_begin = prev_end = prev_offset = -1
                for interval in intervals[pmask]:
                    begin, end, phy = interval

                    offset = self.phy.p2o[phy]
                    if offset == -1:
                        continue

                    if prev_end == begin and prev_offset + (prev_end - prev_begin) == offset:
                        prev_end = end
                    else:
                        fused_intervals.append([prev_begin, prev_end, prev_offset])
                        prev_begin = begin
                        prev_end = end
                        prev_offset = offset

                if prev_begin != begin:
                    fused_intervals.append([prev_begin, prev_end, prev_offset])
                else:
                    offset = self.phy.p2o[phy]
                    if offset == -1:
                        print(f"ERROR!! {phy}")
                    else:
                        fused_intervals.append([begin, end, offset])
                intervals[pmask] = sorted(fused_intervals[1:], key=lambda x: x[1] - x[0], reverse=True)
            
            # Write segments in the new file and fill the program header
            p_offset = len(elf_h)
            offset2p_offset = {} # Slow but more easy to implement (best way: a tree sort structure able to be updated)
            e_phnum = 0
            
            for pmask, interval_list in intervals.items():
                e_phnum += len(interval_list)
                for idx, interval in enumerate(interval_list):
                    begin, end, offset = interval
                    size = end - begin
                    if offset not in offset2p_offset:
                        elf_fd.write(self.phy.get_data_raw(offset, size))
                        if not self.phy.get_data_raw(offset, size):
                            print(hex(offset), hex(size))
                        new_offset = p_offset 
                        p_offset += size
                        for page_idx in range(0, size, self.minimum_page):
                            offset2p_offset[offset + page_idx] = new_offset + page_idx
                    else:
                        new_offset = offset2p_offset[offset]
                    interval_list[idx].append(new_offset) # Assign the new offset in the dest file
                
            # Create the program header containing all the segments (ignoring not in RAM pages)
            e_phoff = elf_fd.tell()
            p_header = bytes()
            for pmask, interval_list in intervals.items():
                for begin, end, offset, p_offset in interval_list:
                    
                    # Workaround Ghidra 32 bit
                    if end == 0xFFFFFFFF + 1 and e_machine == 0x03:
                        end = 0xFFFFFFFF
                    
                    p_filesz = end - begin

                    segment_entry = bytearray(e_phentsize)
                    segment_entry[0x00:0x04] = 0x1.to_bytes(4, endianness)          # p_type
                    segment_entry[0x04:0x08] = pmask.to_bytes(4, endianness)        # p_flags
                    segment_entry[0x10:0x18] = begin.to_bytes(8, endianness)        # p_vaddr
                    segment_entry[0x18:0x20] = offset.to_bytes(8, endianness)       # p_paddr Original offset
                    segment_entry[0x28:0x30] = p_filesz.to_bytes(8, endianness)     # p_memsz
                    segment_entry[0x08:0x10] = p_offset.to_bytes(8, endianness)     # p_offset
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
            if e_phnum < 65536:
                elf_fd.seek(0x38)
                elf_fd.write(e_phnum.to_bytes(2, endianness))         # e_phnum
            else:
                elf_fd.seek(0x28)
                elf_fd.write(s_header_pos.to_bytes(8, endianness))    # e_shoff
                elf_fd.seek(0x38)
                elf_fd.write(0xFFFF.to_bytes(2, endianness))          # e_phnum
                elf_fd.write(0x40.to_bytes(2, endianness))            # e_shentsize
                elf_fd.write(0x1.to_bytes(2, endianness))             # e_shnum

                section_entry = bytearray(0x40)
                section_entry[0x2C:0x30] = e_phnum.to_bytes(4, endianness)  # sh_info
                elf_fd.seek(s_header_pos)
                elf_fd.write(section_entry)

    def _test_elf_reconstruction(self, kernel=True, only_executable=False):
        print("Test ELF reconstruction...")

        # Create an kernel ELF and read parse it
        self.export_virtual_memory_elf("/tmp/elf_test.test", kernel=kernel, only_executable=only_executable)
        
        with open("/tmp/elf_test.test", "rb") as virtual_fd:
            virtual_elf = ELFFile(virtual_fd)
            virtual_mm = mmap(virtual_fd.fileno(), 0, prot=PROT_READ)

            # Check if all the segment in virtual ELF contains the exact same data of the
            # raw ELF
            for segment in virtual_elf.iter_segments():
                s_size = segment["p_filesz"]
                offset = segment["p_offset"]
                old_offset = segment["p_paddr"]

                buf_v = virtual_mm[offset:offset+s_size] # Data from virtual ELF
                buf_p = self.phy.get_data_raw(old_offset, s_size) # Data from raw ELF

                if buf_v != buf_p:
                    print("ERROR! Data at offset {} of size {} is different from data at {}".format(hex(offset), hex(s_size), hex(old_offset)))
                    
            virtual_mm.close()
        os.remove("/tmp/elf_test.test")

class IntelTranslator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(mmu_class, regs_dict, mphy, ignored_pages):
        if mmu_class is IntelAMD64:
            dtb = ((regs_dict["cr3"] >> 12) & ((1 << (mphy - 12)) - 1)) << 12

        elif mmu_class is IntelPAE:
            dtb = ((regs_dict["cr3"] >> 5) & (1 << 27) - 1) << 5

        elif mmu_class is IntelIA32:
            dtb = ((regs_dict["cr3"] >> 12) & (1 << 20) - 1) << 12
            mphy = min(mphy, 40)

        else:
            raise NotImplementedError

        return {"dtb": dtb,
                "wp":  bool((regs_dict["cr0"] >> 16) & 0x1),
                "ac":  bool((regs_dict["eflags"] >> 18) & 0x1),
                "nxe": bool((regs_dict["efer"] >> 11) & 0x1),
                "smep": bool((regs_dict["cr4"] >> 20) & 0x1),
                "smap": bool((regs_dict["cr4"] >> 21) & 0x1),
                "mphy": mphy,
                "ignored_pages": ignored_pages
               }

    @staticmethod
    def derive_translator_class(regs_dict):
        pg =  bool((regs_dict["cr0"] >> 31) & 0x1)
        pae = bool((regs_dict["cr4"] >> 5) & 0x1)
        lme = bool((regs_dict["efer"] >> 8) & 0x1)

        if pg and pae and lme:
            return IntelAMD64
        elif pg and pae:
            return IntelPAE
        elif pg:
            return IntelIA32
        else:
            raise NotImplementedError

    @staticmethod
    def factory(phy, ignored_pages):
        machine_data = phy.get_machine_data()
        regs = machine_data["CPURegisters"]
        mphy = machine_data["CPUSpecifics"]["MAXPHYADDR"]
        if type(mphy) == str and "[D" in mphy:
            mphy = int(mphy[:-2])

        translator_c = IntelTranslator.derive_translator_class(regs)
        mmu_settings = IntelTranslator.derive_mmu_settings(translator_c, regs, mphy, ignored_pages)
        return translator_c(phy=phy, **mmu_settings)


    def __init__(self, dtb, phy, mphy, wp=False, ac=False, nxe=False, smap=False, smep=False):
        super(IntelTranslator, self).__init__(dtb, phy)
        self.mphy = mphy
        self.wp = wp
        self.ac = ac # UNUSED by Fossil
        self.smap = smap
        self.nxe = nxe
        self.smep = smep
        self.minimum_page = 0x1000

        logging.debug(f"Type: {type(self)}, MAX_PHY: {self.mphy}, WP {self.wp}, AC {self.ac}, SMAP {self.smap}, SMEP {self.smep}, NXE {self.nxe}, DTB {hex(self.dtb)}")

        print("Creating resolution trees...")
        self._reconstruct_mappings(self.dtb, upmask=[[False, True, True]])

    def _finalize_virt_addr(self, virt_addr, permissions):
        return virt_addr


class IntelIA32(IntelTranslator):
    def __init__(self, dtb, phy, mphy, wp=True, ac=False, nxe=False, smap=False, smep=False, ignored_pages=[]):
        self.unpack_fmt = "<I"
        self.total_levels = 2
        self.prefix = 0x0
        self.table_sizes = [0x1000, 0x1000]
        self.shifts = [22, 12]
        self.wordsize = 4
        self.ignored_pages = ignored_pages

        super(IntelIA32, self).__init__(dtb, phy, mphy, wp, ac, nxe, smap, smep)

    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, tuple(), 0, 0

        else:
            perms_flags = [[not bool(entry & 0x4),   # K
                            bool(entry & 0x2),       # W
                            True                     # X
                            ]]

            # Upper tables pointers
            if not(entry & 0x80) and (lvl == 0):
                addr = ((entry >> 12) & ((1 << 20) - 1)) << 12
                return True, perms_flags, addr, 0

            # Leaf
            else:
                if lvl == 0:
                    addr = (((entry >> 13) & ((1 << (self.mphy - 32)) - 1)) << 32) | (((entry >> 22) & ((1 << 10) - 1)) << 22)
                else:
                    addr = ((entry >> 12) & ((1 << 20) - 1)) << 12
                return True, perms_flags, addr, 1 << self.shifts[lvl]

    def _reconstruct_permissions(self, pmask):
        k_flags, w_flags, _ = zip(*pmask)

        # Kernel page in kernel mode
        if any(k_flags):
            r = True
            w = all(w_flags) if self.wp else True
            x = True

            return r << 2 | w << 1 | int(x), 0

        # User page in kernel mode
        else:
            r = True if (not self.smap) or (self.smap and self.ac) else False

            if not self.wp:
                w = True if (not self.smap) or (self.smap and self.ac) else False
            else:
                w = all(w_flags) if (not self.smap) or (self.smap and self.ac) else False

            x = True

            return 0, r << 2 | w << 1 | int(x)


class IntelPAE(IntelTranslator):
    def __init__(self, dtb, phy, mphy, wp=True, ac=False, nxe=True, smap=False, smep=False, ignored_pages=[]):
        self.unpack_fmt = "<Q"
        self.total_levels = 3
        self.prefix = 0x0
        self.table_sizes = [0x20, 0x1000, 0x1000]
        self.shifts = [30, 21, 12]
        self.wordsize = 4
        self.ignored_pages = ignored_pages

        super(IntelPAE, self).__init__(dtb, phy, mphy, wp, ac, nxe, smap, smep)

    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, tuple(), 0, 0

        else:
            if lvl == 0:
                perms_flags = [[False, True, True]]
            else:
                perms_flags = [[ not bool(entry & 0x4),              # K
                                bool(entry & 0x2),                   # W
                                not bool(entry & 0x8000000000000000) # X
                                ]]

            # Upper tables pointers
            if (not(entry & 0x80) and lvl < 2) or lvl == 0: # PDPTE does not have leaf
                addr = ((entry >> 12) & ((1 << (self.mphy - 12)) - 1)) << 12
                return True, perms_flags, addr, 0

            # Leaf
            else:
                addr = ((entry >> self.shifts[lvl]) & ((1 << (self.mphy - self.shifts[lvl])) - 1)) << self.shifts[lvl]
                return True, perms_flags, addr, 1 << self.shifts[lvl]

    def _reconstruct_permissions(self, pmask):
        k_flags, w_flags, x_flags = zip(*pmask)

        # Kernel page in kernel mode
        if any(k_flags):
            r = True
            w = all(w_flags) if self.wp else True
            x = all(x_flags) if self.nxe else True

            return r << 2 | w << 1 | int(x), 0

        # User page in kernel mode
        else:
            r = True if (not self.smap) or (self.smap and self.ac) else False

            if not self.wp:
                w = True if (not self.smap) or (self.smap and self.ac) else False
            else:
                w = all(w_flags) if (not self.smap) or (self.smap and self.ac) else False

            if not self.smep:
                x = all(x_flags) if self.nxe else True
            else:
                x = False

            return 0, r << 2 | w << 1 | int(x)


class IntelAMD64(IntelTranslator):
    def __init__(self, dtb, phy, mphy, wp=True, ac=False, nxe=True, smap=False, smep=False, ignored_pages=[]):
        self.unpack_fmt = "<Q"
        self.total_levels = 4
        self.prefix = 0xFFFF800000000000
        self.table_sizes = [0x1000] * 4
        self.shifts = [39, 30, 21, 12]
        self.wordsize = 8
        self.ignored_pages = ignored_pages

        super(IntelAMD64, self).__init__(dtb, phy, mphy, wp, ac, nxe, smap, smep)

    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, tuple(), 0, 0

        else:
            perms_flags = [[ not bool(entry & 0x4),              # K
                            bool(entry & 0x2),                   # W
                            not bool(entry & 0x8000000000000000) # X
                            ]]

            # Upper tables pointers
            if (not(entry & 0x80) and lvl < 3) or lvl == 0: # PTL4 does not have leaf
                addr = ((entry >> 12) & ((1 << (self.mphy - 12)) - 1)) << 12
                return True, perms_flags, addr, 0

            # Leaf
            else:
                addr = ((entry >> self.shifts[lvl]) & ((1 << (self.mphy - self.shifts[lvl])) - 1)) << self.shifts[lvl]
                return True, perms_flags, addr, 1 << self.shifts[lvl]

    def _reconstruct_permissions(self, pmask):
        k_flags, w_flags, x_flags = zip(*pmask)

        # Kernel page in kernel mode
        if any(k_flags):
            r = True
            w = all(w_flags) if self.wp else True
            x = all(x_flags) if self.nxe else True

            return r << 2 | w << 1 | int(x), 0

        # User page in kernel mode
        else:
            r = True if (not self.smap) or (self.smap and self.ac) else False

            if not self.wp:
                w = True if (not self.smap) or (self.smap and self.ac) else False
            else:
                w = all(w_flags) if (not self.smap) or (self.smap and self.ac) else False

            if not self.smep:
                x = all(x_flags) if self.nxe else True
            else:
                x = False

            return 0, r << 2 | w << 1 | int(x)

    def _finalize_virt_addr(self, virt_addr, permissions):
        # Canonical address form
        if virt_addr & 0x800000000000:
            return self.prefix | virt_addr
        else:
            return virt_addr


class RISCVTranslator(AddressTranslator):
    # TODO: missing prefix identification for kernel address space
    @staticmethod
    def derive_mmu_settings(mmu_class, regs_dict, ignored_pages):

        if mmu_class is RISCVSV32:
            dtb = (regs_dict["satp"] & ((1 << 22) - 1)) << 12
        elif mmu_class is RISCVSV39:
            dtb = (regs_dict["satp"] & ((1 << 44) - 1)) << 12
        else:
            raise NotImplementedError

        return {"dtb": dtb,
                "Sum":  bool((regs_dict["sstatus"] >> 18) & 0x1),
                "mxr": bool((regs_dict["sstatus"] >> 19) & 0x1),
                "ignored_pages": ignored_pages
               }

    @staticmethod
    def derive_translator_class(regs_dict):
        satp = regs_dict["satp"]

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

    @staticmethod
    def factory(phy, ignored_pages):

        machine_data = phy.get_machine_data()
        regs = machine_data["CPURegisters"]

        translator_c = RISCVTranslator.derive_translator_class(regs)
        mmu_settings = RISCVTranslator.derive_mmu_settings(translator_c, regs, ignored_pages)
        return translator_c(phy=phy, **mmu_settings)


    def __init__(self, dtb, phy, Sum=True, mxr=True):
        super(RISCVTranslator, self).__init__(dtb, phy)
        self.Sum = Sum
        self.mxr = mxr
        self.minimum_page = 0x1000

        print("Creating resolution trees...")
        self._reconstruct_mappings(self.dtb, upmask=[[False, True, True, True]])

    def _finalize_virt_addr(self, virt_addr, permissions):
        return virt_addr

    def _reconstruct_permissions(self, pmask):
        k_flag, r_flag, w_flag, x_flag = pmask[-1] # No hierarchy

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
    def __init__(self, dtb, phy, Sum, mxr, ignored_pages=[]):
        self.unpack_fmt = "<I"
        self.total_levels = 2
        self.prefix = 0x0
        self.table_sizes = [0x1000, 0x1000]
        self.shifts = [22, 12]
        self.wordsize = 4
        self.ignored_pages = ignored_pages

        super(RISCVSV32, self).__init__(dtb, phy, Sum, mxr)

    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, tuple(), 0, 0

        else:
            k = not bool(entry & 0x10)
            r = bool(entry & 0x2)
            w = bool(entry & 0x4)
            x = bool(entry & 0x8)
            perms_flags = [[k, r, w, x]]

            addr = ((entry >> 10) & ((1 << 22) - 1)) << 12
            # Leaf
            if r or w or x or lvl == 1:
                return True, perms_flags, addr, 1 << self.shifts[lvl]
            else:
                # Upper tables pointers
                return True, perms_flags, addr, 0


class RISCVSV39(RISCVTranslator):
    def __init__(self, dtb, phy, Sum, mxr, ignored_pages=[]):
        self.unpack_fmt = "<Q"
        self.total_levels = 3
        self.prefix = 0x0
        self.table_sizes = [0x1000, 0x1000, 0x1000]
        self.shifts = [30, 21, 12]
        self.wordsize = 8
        self.ignored_pages = ignored_pages

        super(RISCVSV39, self).__init__(dtb, phy, Sum, mxr)

    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, tuple(), 0, 0

        else:
            k = not bool(entry & 0x10)
            r = bool(entry & 0x2)
            w = bool(entry & 0x4)
            x = bool(entry & 0x8)
            perms_flags = [[k, r, w, x]]

            addr = ((entry >> 10) & ((1 << 44) - 1)) << 12
            # Leaf
            if r or w or x or lvl == 2:
                return True, perms_flags, addr, 1 << self.shifts[lvl]
            else:
                # Upper tables pointers
                return True, perms_flags, addr, 0


class ARMTranslator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(mmu_class, regs_dict, ignored_pages):
        if mmu_class is ARMShort:
            dtb = ((regs_dict["ttbr1"] >> 14) & ((1 << 18) - 1)) << 14
            ee = bool((regs_dict["sctlr"] >> 25) & 0x1)
            afe = bool(((regs_dict["sctlr"] >> 29) & 0x1))
        else:
            raise NotImplementedError

        return {"dtb": dtb,
                "ee": ee,
                "afe": afe,
                "ignored_pages": ignored_pages}

    @staticmethod
    def derive_translator_class(regs_dict):
        eae = regs_dict["ttbcr"] & 0x80000000

        if not eae:
            return ARMShort
        else:
            raise NotImplementedError

    @staticmethod
    def factory(phy, ignored_pages):

        machine_data = phy.get_machine_data()
        regs = machine_data["CPURegisters"]

        # QEMU exports TTBR0/1/TTBCR/SCTLR with different names (SUPPOSING NO SECURE MEMORY)
        ttbr0 = 0
        for reg_name in ["TTBR0", "TTBR0_S", "TTBR0_EL1", "TTBR0_EL1_S"]:
            if regs.get(reg_name, ""):
                ttbr0 = regs[reg_name]
                break

        ttbr1 = 0
        for reg_name in ["TTBR1", "TTBR1_S", "TTBR1_EL1", "TTBR1_EL1_S"]:
            if regs.get(reg_name, ""):
                ttbr1 = regs[reg_name]
                break

        ttbcr = 0
        for reg_name in ["TTBCR", "TTBCR_S", "TCR_EL1", "TCR_EL3"]:
            if regs.get(reg_name, ""):
                ttbcr = regs[reg_name]
                break
        regs["ttbcr"] = ttbcr

        sctlr = 0
        for reg_name in ["SCTLR", "SCTLR_S"]:
            if regs.get(reg_name, ""):
                ttbcr = regs[reg_name]
                break
        regs["sctlr"] = sctlr

        # If TTBCR.N is 0 use TTBR0 as TTBR1
        regs["ttbr0"] = ttbr0
        regs["ttbr1"] = ttbr1 if (regs["ttbcr"] & 0x7) else ttbr0


        translator_c = ARMTranslator.derive_translator_class(regs)
        mmu_settings = ARMTranslator.derive_mmu_settings(translator_c, regs, ignored_pages)
        return translator_c(phy=phy, **mmu_settings)


    def __init__(self, dtb, phy, ee=False, afe=False):
        super(ARMTranslator, self).__init__(dtb, phy)

        print("Creating resolution trees...")
        self._reconstruct_mappings(self.dtb, upmask=[[True, True, True, True, True, True]])

    def _finalize_virt_addr(self, virt_addr, permissions):
        return virt_addr

    def _reconstruct_permissions(self, pmask):
        kr_flags, kw_flags, kx_flags, ur_flags, uw_flags, ux_flags = zip(*pmask) # Partially hierarchical

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

    def __init__(self, dtb, phy, ee, afe, ignored_pages=[]):
        self.unpack_fmt = ">I" if ee else "<I"
        self.total_levels = 2
        self.prefix = 0x0
        self.table_sizes = [0x4000, 0x400]
        self.shifts = [20, 12]
        self.ee = ee
        self.afe = afe
        self.wordsize = 4
        self.minimum_page = 0x1000
        self.ignored_pages = ignored_pages

        super(ARMShort, self).__init__(dtb, phy, ee, afe)

    def _return_short_pmask(self, ap, kx, ux):
        if self.afe: # AP[2:1] mode
            if ap == 0:
                return [[True, True, kx, False, False, ux]]
            elif ap == 1:
                return [[True, True, kx, True, True, ux]]
            elif ap == 2:
                return [[True, False, kx, False, False, ux]]
            else:
                return [[True, False, kx, True, False, ux]]

        else: # AP[2:0] mode
            if ap == 0 or ap == 4:
                return [[False, False, kx, False, False, ux]]
            elif ap == 1:
                return [[True, True, kx, False, False, ux]]
            elif ap == 2:
                return [[True, True, kx, True, False, ux]]
            elif ap == 3:
                return [[True, True, kx, True, True, ux]]
            elif ap == 5:
                return [[True, False, kx, False, False, ux]]
            else:
                return [[True, False, kx, True, False, ux]]


    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)
        t_flag = entry & 0x3

        # Empty entry
        if t_flag == 0:
            return False, tuple(), 0, 0

        if lvl == 0:
            # Upper tables pointers
            if t_flag == 1:
                addr = ((entry >> 10) & ((1 << 22) - 1)) << 10
                perm_flags = [[True, True, not bool(entry & 0x4), True, True, True]]
                return True, perm_flags, addr, 0

            # Leaves
            else:
                kx = not bool(entry & 0x1)
                ux = not bool(entry & 0x10)
                ap = (((entry >> 15) & 0x1) << 2) | ((entry >> 10) & 0x3)
                perm_flags = self._return_short_pmask(ap, kx, ux)

                if not ((entry >> 18) & 0x1): # Section
                    addr = ((entry >> 20) & ((1 << 12) - 1)) << 20
                    off_size = 20
                else: # Supersection
                    # Super Section entries are repeated 16 times, use only the first one
                    if idx % 16 != 0:
                        return False, tuple(), 0, 0
                    addr = (((entry >> 5) & ((1 << 4) - 1)) << 36) | (((entry >> 20) & ((1 << 4) - 1)) << 32) | ((entry >> 24) & ((1 << 8) - 1)) << 24
                    off_size = 24
                return True, perm_flags, addr, 1 << off_size

        else:

            # Large page
            if t_flag == 1:
                # Large pages entries are repeated 16 times, use only the first one
                if idx % 16 != 0:
                    return False, tuple(), 0, 0
                ux = not bool(entry & 0x8000)
                addr = ((entry >> 16) & ((1 << 16) - 1)) << 16
                off_size = 16

            # Small page
            else:
                addr = ((entry >> 12) & ((1 << 20) - 1)) << 12
                ux = not bool(entry & 0x1)
                off_size = 12

            ap = (((entry >> 9) & 0x1) << 2) | ((entry >> 4) & 0x3)
            perm_flags = self._return_short_pmask(ap, True, ux)
            return True, perm_flags, addr, 1 << off_size


class AArch64Translator(AddressTranslator):
    @staticmethod
    def derive_mmu_settings(mmu_class, regs_dict, ignored_pages):
        # We ignore PSTATE.PAN, PSTATE.UAO

        if mmu_class is AArch64Long:
            tcr = regs_dict["tcr_el1"]
            tg1 =  (tcr >> 30) & 0x3
            t1sz = (tcr >> 16) & 0x3F
            t1sz = max(t1sz, 16) # 21?

            # Determine which part of the top table address is inserted into TTBR1_EL1
            tree_struct = AArch64Long._get_tree_struct(t1sz, tg1)
            x = AArch64Long._calculate_x(tree_struct[0], tree_struct[1], t1sz)
            print(x)
            dtb = ((regs_dict["ttbr1_el1"] >> x) & ((1 << 47 - x + 1) - 1)) << x

            ee = bool((regs_dict["sctlr_el1"] >> 25) & 0x1)
            hpd1 = not bool(((tcr >> 42) & 0x1))
            wxn = bool(((regs_dict["sctlr_el1"] >> 19) & 0x1))
        else:
            raise NotImplementedError

        return {"dtb": dtb,
                "t1sz": t1sz,
                "tg1": tg1,
                "ee": ee,
                "hpd1": hpd1,
                "wxn": wxn,
                "ignored_pages": ignored_pages}

    @staticmethod
    def derive_translator_class(regs_dict):
        # I haven't find a way to distinguisch Long to LongLPA modes...
        return AArch64Long

    @staticmethod
    def factory(phy, ignored_pages):

        machine_data = phy.get_machine_data()
        regs = machine_data["CPURegisters"]

        # QEMU exports TTBR0_EL1/TTBR1_EL1/TCR_EL1/SCTLR_EL1 with different names (SUPPOSING NO SECURE MEMORY)
        ttbr0 = 0
        for reg_name in ["TTBR0_EL1", "TTBR0_EL1_S"]:
            if regs.get(reg_name, ""):
                ttbr0 = regs[reg_name]
                break

        ttbr1 = 0
        for reg_name in ["TTBR1_EL1", "TTBR1_EL1_S"]:
            if regs.get(reg_name, ""):
                ttbr1 = regs[reg_name]
                break

        tcr = 0
        for reg_name in ["TCR_EL1", "TCR_EL1_S"]:
            if regs.get(reg_name, ""):
                tcr = regs[reg_name]
                break
        regs["tcr_el1"] = tcr

        sctlr = 0
        for reg_name in ["SCTLR", "SCTLR_S"]:
            if regs.get(reg_name, ""):
                sctlr = regs[reg_name]
                break
        regs["sctlr_el1"] = sctlr

        # TODO: If not TTBR1 use TTBR0 as TTBR1 (monospace OSs, not tested!)
        regs["ttbr0_el1"] = ttbr0
        regs["ttbr1_el1"] = ttbr1 if ttbr1 else ttbr0

        translator_c = AArch64Translator.derive_translator_class(regs)
        mmu_settings = AArch64Translator.derive_mmu_settings(translator_c, regs, ignored_pages)
        return translator_c(phy=phy, **mmu_settings)


    def __init__(self, dtb, phy, t1sz, tg1, ee=False, hpd1=False, wxn=False):
        super(AArch64Translator, self).__init__(dtb, phy)

        print("Creating resolution trees...")
        self._reconstruct_mappings(self.dtb, upmask=[[True, True, True, True, True, True]])

    def _finalize_virt_addr(self, virt_addr, permissions):
        raise NotImplementedError

    def _reconstruct_permissions(self, pmask):
        kr_flags, kw_flags, kx_flags, ur_flags, uw_flags, ux_flags = zip(*pmask)

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

    def _return_pmask(self, ap, kx, ux):
        if ap == 0:
            return [[True, True, kx, False, False, ux]]
        elif ap == 1:
            return [[True, True, kx, True, True, ux]]
        elif ap == 2:
            return [[True, False, kx, False, False, ux]]
        else:
            return [[True, False, kx, True, False, ux]]

    def _return_pmask_aptable(self, ap, kx, ux):
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
    def _get_tree_struct(t1sz, tg1):
        if tg1 == 1:
            granule = 16384
        elif tg1 == 2:
            granule = 4096
        elif tg1 == 3:
            granule = 65536
        else:
            raise ValueError

        if granule == 4096:
            if 12 <= t1sz <= 24:
                t = (0, 1 << (28 - t1sz))
            elif 25 <= t1sz <= 33:
                t = (1, 1 << (37 - t1sz))
            elif 34 <= t1sz <= 42:
                t = (2, 1 << (46 - t1sz))
            else:
                t = (3, 1 << (55 - t1sz))

        elif granule == 16384:
            if t1sz == 16:
                t = (0, 16)
            elif 17 <= t1sz <= 27:
                t = (1, 1 << (31 - t1sz))
            elif 28 <= t1sz <= 38:
                t = (2, 1 << (42 - t1sz))
            else:
                t = (3, 1 << (53 - t1sz))

        elif granule == 65536:
            if 12 <= t1sz <= 21:
                t = (1, 1 << (25 - t1sz))
            elif 22 <= t1sz <= 34:
                t = (2, 1 << (38 - t1sz))
            else:
                t = (3, 1 << (51 - t1sz))
        else:
            raise ValueError

        return (granule, 4 - t[0], t[1]) # (granule, levels, top_table_size)

    @staticmethod
    def _calculate_x(granule, levels, t1sz):
        print(granule, levels, t1sz)
        if granule == 4096:
            step = 9
            max_value = 55
        elif granule == 16384:
            step = 11
            max_value = 53
        else:
            step = 13
            max_value = 51
        return (max_value - (levels - 1) * step) - t1sz

    def __init__(self, dtb, phy, t1sz, tg1, ee, hpd1, wxn, ignored_pages=[]):

        self.unpack_fmt = ">Q" if ee else "<Q"
        tree_struct = AArch64Long._get_tree_struct(t1sz, tg1)

        self.total_levels = tree_struct[1]
        self.prefix = (1 << 64) - (1 << (64 - t1sz))
        granule, levels, top_size = tree_struct
        self.table_sizes = [top_size if lvl==0 else granule for lvl in range(levels)]
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
        self.granule = tree_struct[0]
        self.minimum_page = self.granule
        self.ignored_pages = ignored_pages
        
        super(AArch64Long, self).__init__(dtb, phy, t1sz, tg1, ee, hpd1, wxn)

    def _read_entry(self, idx, entry, lvl):
        # Return (is_Valid, Permissions flags, Table Address, Size)

        # Empty entry
        if not (entry & 0x1):
            return False, tuple(), 0, 0

        # First levels
        if (lvl + 1 < self.total_levels):
            # Block entry
            if (entry & 0x3) == 1:
                if self.granule == 0x1000:
                    if lvl == 0:
                        n = 30
                    else:
                        n = 21
                elif self.granule == 0x4000:
                    n = 25
                else:
                    n = 29

                addr = ((entry >> n) & ((1 << 47 - n + 1) - 1)) << n
                ap = (entry >> 6) & 0x3
                kx = not bool((entry >> 53) & 0x1)
                ux = not bool((entry >> 54) & 0x1)
                pmask = self._return_pmask(ap, kx, ux)
                return True, pmask, addr, 1 << n

            # Page table pointer
            else:
                if self.granule == 0x1000:
                    m = 12
                elif self.granule == 0x4000:
                    m = 14
                else:
                    m = 16
                addr = ((entry >> m) & ((1 << 47 - m + 1) - 1)) << m
                ap = (entry >> 61) & 0x3
                kx = not bool((entry >> 59) & 0x1)
                ux = not bool((entry >> 60) & 0x1)
                pmask = self._return_pmask_aptable(ap, kx, ux)
                return True, pmask, addr, 0

        else:
            # Reserved entry:
            if entry & 0x3 == 1:
                return False, tuple(), 0, 0

            # Page
            else:
                if self.granule == 0x1000:
                    addr = ((entry >> 12) & ((1 << 36) - 1)) << 12
                    n = 12
                elif self.granule == 0x4000:
                    addr = ((entry >> 14) & ((1 << 34) - 1)) << 14
                    n = 14
                else:
                    addr = (((entry >> 12) & 0xF) << 48) | (((entry >> 16) & ((1 << 32) - 1)) << 16)
                    n = 16

                ap = (entry >> 6) & 0x3
                kx = not bool((entry >> 53) & 0x1)
                ux = not bool((entry >> 54) & 0x1)
                pmask = self._return_pmask(ap, kx, ux)
                return True, pmask, addr, 1 << n

    def _finalize_virt_addr(self, virt_addr, permissions):
        return self.prefix | virt_addr
