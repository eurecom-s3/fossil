# Fossil
Fossil is a tool for OS-agnostic data structures recovery.
This tool is a Proof-of-Concept of the technique described in the research paper [An OS-agnostic Approach to Memory Forensics](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) by Andrea Olivieri, Matteo dell'Amico and Davide Balzarotti, presented at NDSS 2023.
## Modules
This tool is composed by different modules:
- `qemu_elf_dumper.py`: dumps the physical memory of a QEMU virtual machine into an ELF core file along with some other information about the hardware of the machine (archived in JSON format inside a NOTE ELF header segment)
- `extract_features.py`: scans the VM core dump looking for strings, kernel pointers and performing static analysis using Ghidra
- `doubly_linked_lists.py`: matches extracted pointers to find doubly linked lists
- `trees.py`: extracts binary tress from the VM dump
- `extract_structs.py`: reorganizes structures extracted by the other scripts and extracts arrays, linked lists, derived structures and children structures
- `fossil.py`: an interactive shell to explore the results
## Installation
This tool is tested on Debian 12. Please install all the packages contained in `debian_12_packages`.
It's also possible to run a Docker container containing Fossil and its dependencies (check the Docker section below).
### Installation steps
- Clone this repository and create a python3 virtual environment (`python3 -m venv venv`) and activate it (`source venv/bin/activate`)
- From the virtual environment install python3 dependencies         (`python3 -m pip install -r requirements.txt`)
- Build the Cython module with `python3 setup.py build_ext --inplace`
- Allow your virtual environment to access to the system-wide installed python library `graph-tools` (``echo "/usr/lib/python3/dist-packages" > `find venv -name site-packages` /dist-packages.pth``)
- Download [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases). This tool is tested with versions `10.1.2` and `10.3.2`. Once installed, it is recommended to set the following environment variable `GHIDRA_PATH=/path/to/ghidra`
- Increase memory available to Ghidra with `sed -i s/MAXMEM=2G/MAXMEM=8G/g $GHIDRA_PATH/support/analyzeHeadless`
## How to use
### Data dumping
- Create a QEMU Virtual Machine with your favorite OS running on a `i386`, `x86_64` or `aarch64` CPU architecture (`Intel PAE` is not tested)
- Start the VM **without enabling KVM** exposing the `QMP` and `GDB` services (`qemu [...] -qmp tcp::xxxx,server -s`). These two options open a `QMP` server on `localhost:xxxx` and a `GDB` server on `localhost:1234`
- On a different terminal session run `qemu_elf_dumper.py 127.0.0.1:xxxx 127.0.0.1:1234 /path/to/existing_output_folder`. When you want to dump the VM press CTRL-C: the script will stop the machine, dump the physical memory and save information on an ELF core file.
	- If you are running an Intel machine, the command to use is `qemu_elf_dumper.py 127.0.0.1:xxxx 127.0.0.1:1234 -c CPUSpecifics:MAXPHYADDR:YYY`, where `YYY` is the `MAX PHYSICAL ADDRESS` value of the emulated CPU. To do this run the VM as above and, once inside, run on a terminal `cat /proc/cpuinfo | grep "address sizes"`.  The `MAX_PHY` value is equal to the `bits physical` value.
- Once the dumping is finished, you can move along to `data extraction`. You can either follow the instructions below or use the `dry_run.py` script. This last one simply performs in order the following steps using the default values provided by each script.
### Data extraction
- Extract pointers, strings, other metadata and perform static analysis on the ELF core dump using `extract_features.py /path/to/dump.elf /path/to/existing_path_to_results/`. This script produces various `extracted_xxx.lzma` compressed pickle files. This step can be very long due to the Ghidra static analysis phase.
- Extract the doubly linked lists using `doubly_linked_lists.py --min-offset N_OFF --max-offset P_OFF --offset-step ALPHA --min-size SIZE /path/to/results/extracted_ptrs.lzma /path/to/results/dll.lzma`. This step can be very long and consume a huge amount of RAM.
	- `N_OFF`: the minimum offset (negative)  
	- `P_OFF`: the maximum offset (positive)
	- These values represent the minimum and maximum offsets used for looking for next-prev relations between pointers. The higher the values, the longer is the execution time. In the tests, we used `8192` for 64-bit OS and `4096` for 32-bit ones, but for normal uses it can be possible to reduce them. Those values must be:
		- One the opposite of the other (i.e. `P_OFF = - N_OFF`)
		- A power of 2 (i.e. `P_OFF = 2^x`)
		- A multiple of `ALPHA` (i.e. `P_OFF mod ALPHA == 0`)
	- `ALPHA`: is the pointer size used by the OS (8 for a 64-bit CPU, 4 for a 32-bit CPU)
	- `SIZE`: is the minimum length of a doubly linked list. The lower the value, the greater the execution time, the RAM required and the number of results (including false positives). Check out the [paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) for more information.
- Extract all the binary trees with `trees.py --min-offset N_OFF --max-offset P_OFF --offset-step ALPHA /path/to/results/extracted_ptrs.lzma /path/to/results/trees.lzma`. The number of results dramatically increases with the increase of the `P_OFF/N_OFF` absolute value. In the tests, we used `64` for 64-bit OS and `32` for 32-bit OS. The higher the value, the greater the execution time, the RAM required and the number of results (including false positives). Check out the [paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) for more information.
- Reorganize and filter structures using `extract_structs.py /path/to/data`. The path should contain the output of the previous scripts. This script produces `/path/to/data/results.lzma` compressed pickle file which can be explored using `fossil.py`.
- Explore the results with the interactive fossil shell `fossil.py /path/to/data`. Example of fossil shell commands:
	- Look for a string in a circular doubly linked list: `find_string -cdl bash`
	- Show all the strings in the same data structure at a fixed offset: `expand_struct -cdl 103 720`
	- Perform a zero knowledge search in a circular doubly linked lists: `zero -cdl`
## Docker
It is possible to build and use a Docker/Podman container including the entire fossil suite. The following commands refer to `podman`, but should be exactly the same with `docker`.
- Clone this repository, enter in the repository directory and run `podman build -t fossil .` to build the container.
- Inside the container, fossil is located at `/fossil` and requires to bind a volume to `/data` which will contain input and output files. The container installs and uses Ghidra 10.3.2. If you want to use a different Ghidra version, put it in the `/data` volume on the host and add the option `-e GHIDRA_PATH=/data/GHIDRA_INSTALL_DIR`.
- To call a fossil script run `podman run --network="host" --rm --it --volume HOST_PATH_TO_DATA:/data:Z localhost/fossil:latest /fossil/COMMAND [options]`
	- Example: in order to extract doubly linked lists having data in `/path/to/dumps` on the host execute
	  ```bash
	  podman run --network="host" --rm --it --volume /path/to/dumps:/data:Z localhost/fossil:latest /fossil/doubly_linked_lists.py --min-offset -8192 --max-offset 8192 --offset-step 8 --min-size 3 /data/extracted_ptrs.lzma /data/dll.lzma
	  ```
- To run `qemu_elf_dumper.py` run `qemu` on the host machine and call `qemu_elf_dumper.py` inside the container with an extra option: if the bounded host path is `HOST_PATH_TO_DATA` add `-d HOST_PATH_TO_DATA` option to the command line