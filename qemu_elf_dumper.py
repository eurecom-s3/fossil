#!/usr/bin/env -S python3 -u

from qmp import QEMUMonitorProtocol
from signal import signal, SIGINT
import argparse
from datetime import datetime
from pygdbmi.gdbcontroller import GdbController, DEFAULT_GDB_LAUNCH_COMMAND
import os
import errno
import re
import json
import shutil
import threading

start_time_g = 0
qemu_monitor = None
gdbmi = None
little_endian = False
dump_fifo = None
path = None
custom_values = []

def ctrl_c_handler(sig, frame):
    global start_time_g
    global qemu_monitor
    global gdbmi
    global dump_fd
    global dump_fifo

    uptime = (datetime.now() - start_time_g).total_seconds()
    print("\n\nSave registers and dump memory")

    # Stop machine, grab registers values and dump the memory
    qemu_monitor.cmd("stop", {})

    # Create ELF header
    architecture = qemu_monitor.cmd("query-target")["return"]["arch"]
    elf_h = make_elf_header(architecture, little_endian)

    # Create machine ELF NOTE
        # Dump registers
    gdbmi.write('help') # Workaround
    gdb_reg_reply = gdbmi.write('info all-registers')
    registers = extract_registers_values(gdb_reg_reply)

        # Get memory regions
    mem_regions_raw = qemu_monitor.cmd("human-monitor-command", {"command-line": "info mtree -f"})["return"]
    mem_regions = split_mtree_data(mem_regions_raw)
    mem_regions_data = [(x[0], x[3]) for x in mem_regions if x[2] != "ram"]
    machine_data = {"Architecture": architecture,
                    "Uptime": uptime,
                    "CPURegisters": registers,
                    "MemoryMappedDevices": mem_regions_data
                    }

    # Add custom values
    for cv in custom_values:
        reg_key, key, value = cv[0].split(":")
        try:
            value = int(value, 0)
        except:
            pass
        if reg_key not in machine_data:
            machine_data[reg_key] = {}
        machine_data[reg_key][key] = value

        # Creare machine note
    machine_note = make_note_segment(little_endian, "FOSSIL", machine_data, 0xDEADC0DE)
    notes = [[len(machine_note)]]

    # Create ELF Program Header and calulate p_offset for each segment
    program_h = make_program_header(elf_h, notes, mem_regions)

    # Write headers
    dump_fd.write(elf_h + program_h + machine_note)

    def call_pmemsave(qemu_monito, r_start, r_size):
        qemu_monitor.cmd("pmemsave", {"val": r_start, "size": r_size, "filename": path + "dump_fifo"})

    # Dump memory regions
    for region in mem_regions:
        r_start, r_end, r_type, _ = region

        if r_type != "ram":
            continue

        r_size = r_end - r_start + 1
        th = threading.Thread(target=call_pmemsave, args=(qemu_monitor, r_start, r_size))
        th.start()
        fifo_fd = open(path + "dump_fifo", "rb")
        shutil.copyfileobj(fifo_fd, dump_fd)
        th.join()
        fifo_fd.close()
    dump_fd.close()

    # Unfreeze the machine and close monitors
    qemu_monitor.cmd("cont", {})
    qemu_monitor.close()
    gdbmi.exit()
    try:
        os.remove(path + "dump_fifo")
    except FileNotFoundError:
        pass

    print("Done!")
    exit(0)

def split_mtree_data(mtree):

    lines = mtree.split("\r\n")
    for i, line in enumerate(lines):
        if line.strip() == "Root memory region: system":
            break

    regions = []
    expr = re.compile(r"\s*(?P<r_start>[0-9abcdef]{1,})-(?P<r_end>[0-9abcdef]{1,})\s+\(prio\s+-?\d+,\s+(?P<r_type>.+)\):\s+(?P<r_name>.+)")
    for line in lines[i:]:
        if not line:
            break

        parsed_line = expr.fullmatch(line)
        if not parsed_line:
            continue

        if "@" in parsed_line.group("r_name") and "ram" in parsed_line.group("r_name"):
            region_name =  "ram"
        else:
            region_name = parsed_line.group("r_name")

        region = [int(parsed_line.group("r_start"), 16),
                  int(parsed_line.group("r_end"), 16),
                  parsed_line.group("r_type"),
                  region_name
                 ]

        regions.append(region)

    return regions

def make_note_segment(little_endian, name, descr, n_type):
    pad = 4

    if little_endian:
        endianness = "little"
    else:
        endianness = "big"

    name_b = name.encode()
    name_b += b"\x00"
    namesz = len(name_b).to_bytes(pad, endianness)
    name_b += bytes(pad - (len(name_b) % pad))

    descr_b = json.dumps(descr).encode()
    descr_b += b"\x00"
    descr_b += bytes(pad - (len(descr_b) % pad))
    descrsz = len(descr_b).to_bytes(pad, endianness)

    return namesz + descrsz + n_type.to_bytes(pad, endianness) + name_b + descr_b


def make_elf_header(machine, little_endian):

    # Create ELF main header
    endianness = "little" if little_endian else "big"
    if machine == "aarch64":
        e_machine = 0xB7
    elif machine == "arm":
        e_machine = 0x28
    elif machine == "riscv32":
        e_machine = 0xF3
    elif machine == "riscv64":
        e_machine = 0xF3
    elif machine == "x86_64":
        e_machine = 0x3E
    elif machine == "i386":
        e_machine = 0x03
    else:
        raise Exception("Unknown architecture")

    e_ehsize = 0x40

    elf_h = bytearray(e_ehsize)
    elf_h[0x00:0x04] = b'\x7fELF'                                   # Magic
    elf_h[0x04] = 2                                                 # Elf type
    elf_h[0x05] = 1 if little_endian else 2                         # Endianness
    elf_h[0x06] = 1                                                 # Version
    elf_h[0x10:0x12] = 0x4.to_bytes(2, endianness)                  # e_type
    elf_h[0x12:0x14] = e_machine.to_bytes(2, endianness)            # e_machine
    elf_h[0x14:0x18] = 0x1.to_bytes(4, endianness)                  # e_version
    elf_h[0x34:0x36] = e_ehsize.to_bytes(2, endianness)             # e_ehsize

    return elf_h

def make_program_header(elf_h, notes, mem_regions):
    endianness = "little" if elf_h[0x5] == 1 else "big"
    p_header = bytearray()
    e_phentsize = 0x38
    p_offset = len(elf_h) + (len(notes) + len(mem_regions)) * e_phentsize

    # Create PT_NOTE entries
    for i, note in enumerate(notes):

        note_entry = bytearray(e_phentsize)
        note_entry[0x00:0x04] = 0x4.to_bytes(4, endianness)         # p_type
        note_entry[0x08:0x10] = p_offset.to_bytes(8, endianness)    # p_offset
        note_entry[0x20:0x28] = note[0].to_bytes(8, endianness)     # p_filesz

        notes[i].append(p_offset)
        p_offset += note[0]
        p_header += note_entry

    # Create PT_LOAD entries
    for i, mem_region in enumerate(mem_regions):

        r_start, r_end, r_type, _ = mem_region

        segment_entry = bytearray(e_phentsize)
        segment_entry[0x00:0x04] = 0x1.to_bytes(4, endianness)          # p_type

        if r_type == "ram":                                             # p_flags
            segment_entry[0x04:0x08] = 0x7.to_bytes(4, endianness)
        elif r_type == "rom":
            segment_entry[0x04:0x08] = 0x5.to_bytes(4, endianness)
        else:
            segment_entry[0x04:0x08] = 0x6.to_bytes(4, endianness)

        segment_entry[0x08:0x10] = p_offset.to_bytes(8, endianness)     # p_offset
        segment_entry[0x10:0x18] = r_start.to_bytes(8, endianness)      # p_vaddr
        segment_entry[0x18:0x20] = r_start.to_bytes(8, endianness)      # p_paddr
        p_filesz = (r_end - r_start + 1)

        if r_type == "ram":
            segment_entry[0x20:0x28] = p_filesz.to_bytes(8, endianness) # p_filesz
            p_offset += p_filesz

        segment_entry[0x28:0x30] = p_filesz.to_bytes(8, endianness)     # p_memsz

        p_header += segment_entry

    # Complete ELF header
    elf_h[0x20:0x28] = 0x40.to_bytes(8, endianness)                              # e_phoff
    elf_h[0x36:0x38] = e_phentsize.to_bytes(2, endianness)                       # e_phentsize
    elf_h[0x38:0x3A] = (len(notes) + len(mem_regions)).to_bytes(2, endianness)   # e_phnum

    return p_header

def extract_registers_values(gdb_message):
    regs = {}
    expr = re.compile(r"(?P<reg>\w+)\s+(?P<value>0x[0-9a-fA-F]+).+")


    for msg in gdb_message:

        if msg["message"] == "done":
            continue
        parsed_payload = expr.fullmatch(msg["payload"].strip())
        if parsed_payload:
            regs[parsed_payload.group("reg")] = int(parsed_payload.group("value"), 16)

    return regs

def main():
    global start_time_g
    global qemu_monitor
    global gdbmi
    global dump_fd
    global little_endian
    global path
    global custom_values

    parser = argparse.ArgumentParser(description='You have to call QEMU with "-qmp tcp:HOST:PORT,server -s" options')
    parser.add_argument("qmp", help="QEMU QMP channel (host:port)", type=str)
    parser.add_argument("gdb", help="QEMU GDB channel (host:port)", type=str)
    parser.add_argument("filename", help="Prefix for ELF dump and regs file.", type=str)
    parser.add_argument("-c", help="Add custom values KEY_DICT:KEY:VALUE", action='append', nargs='+', default=[], metavar="KEY_DICT:KEY:VALUE")
    parser.add_argument("-r", help="Enable patch to support GDB RISC-V stub", type=str, metavar="GDB_PATH")
    args = parser.parse_args()

    custom_values = args.c
    gdb_patch = args.r
    try:
        qemu_qmp = args.qmp.split(":")
        qemu_qmp[1] = int(qemu_qmp[1])
        qemu_qmp = tuple(qemu_qmp)
    except Exception as e:
        parser.error("Invalid QMP channel format!")
        exit(1)

    # Create dump file
    try:
        dump_fd = open(args.filename, "wb")
    except Exception as e:
        print(e)
        print("Unable to open output file!")
        exit(1)
    path = os.path.dirname(os.path.abspath(args.filename)) + "/"

    # Create dump fifo
    try:
        os.mkfifo(path + "dump_fifo")
    except OSError as oe:
        if oe.errno != errno.EEXIST:
            print(oe)
            exit(1)

    # Try to open the QMP channel
    try:
        qemu_monitor = QEMUMonitorProtocol(qemu_qmp)
        qemu_monitor.connect()
    except Exception as e:
        print(e)
        print("Impossible to connect to QEMU QMP channel!")
        exit(1)
    print("QEMU QMP connected!")

    # Try to open GDB channel
    try:
        gdb_cmd = DEFAULT_GDB_LAUNCH_COMMAND.copy()
        if gdb_patch:
            gdb_cmd[0] = gdb_patch
            gdb_path = os.path.dirname(os.path.abspath(args.filename))
            gdb_cmd.append(f"--data-directory={gdb_path}/data-directory")

        gdbmi = GdbController(gdb_cmd)

        if gdb_patch:
            gdbmi.write("set architecture riscv")

        gdbmi.write(f'target remote {args.gdb}')
        start_time_g = datetime.now()
        little_endian = True if "little" in gdbmi.write("show endian")[1]["payload"] else False
        gdbmi.write('continue')
    except Exception as e:
        print(e)
        print("Unable to open GDB channel!")
        exit(1)


    signal(SIGINT, ctrl_c_handler)
    print("Press CTRL-C to dump the memory, save the registers, and shutdown the machine")
    while(True):
        pass

if __name__ == "__main__":
    main()
