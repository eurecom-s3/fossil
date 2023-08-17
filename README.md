# Fossil
OS-agnostic tool for data structures recovery.
This tool is a PoC of the technique described in research paper [```"An OS-agnostic Approach to Memory Forensics"```](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) by Andrea Oliveri, Matteo Dell'Amico and Davide Balzarotti presented at NDSS 2023.

The tool is composed by various moduli:
- ```qemu_elf_dumper.py``` dumps the physical memory of a QEMU virtual machine in an ELF core file along with other information about the hardware of the machine (archived in a JSON inside a ```NOTE``` ELF segment).
- ```extract_features.py``` scans the VM core dump looking for kernel pointers, strings and performing static analysis using Ghidra.
- ```bdh_doubly_linked_lists.py``` matches extracted pointers to find doubly linked lists.
- ```compute_chains.py``` extracts linked lists.
- ```trees.py``` extracts binary trees from the VM dump.
- ```extract_structs.py``` reorganizes structures extracted by the other scripts and extracts arrays.
- ```fossil.py```, an interactive shell to explore the results. 

## Installation
The tool is tested on Debian 12. Please install all the packages contained in [```debian_12_packages```](debian_12_packages). If you are running a different Linux distribution or you don't want to install software on your machine you can run a Docker container containing Fossil and its dependencies (check the Docker session in this README).
- Clone this repo than create a python3 virtual environment with ```python3 -m venv venv``` and activate it with ```source venv/bin/activate```.
- From the virtual environment install all the python3 dependencies with ```pip3 install -r requirements.txt```
- Build the Cython module with ```python3 setup.py build_ext --inplace```  and permit to your virtual environment to access to the ```graph-tools``` python library installed system-wide ```echo "/usr/lib/python3/dist-packages" > `find venv -name site-packages`/dist-packages.pth```
- Download Ghidra version that you want to use for static analysis from Ghidra [site](https://github.com/NationalSecurityAgency/ghidra/releases). The tool is tested with versions 10.1.2 (the version used to perform experiments presented in the research paper) and version 10.3.2. Different Ghidra versions can produce different results due to changes in Ghidra code. Unpack the ZIP archive and set the environment variable ```GHIDRA_PATH``` to the directory containing Ghidra (otherwise you have to pass the path manually to ```extract_features.py``` script).
- Increase memory available to Ghidra ```analyzeHeadless``` patching it with ```sed -i s/MAXMEM=2G/MAXMEM=8G/g $GHIDRA_PATH/support/analyzeHeadless```

## How to use it
- Create a QEMU VM of the desired OS running on i386, x86_64 or aarch64 CPU architecture (the tool supports also Intel PAE mode but it is not tested). We have tested our tool with VMs with a maximum of 4GB of RAM, performing analysis on a 16 core 128 GB of RAM machine. We **suppose** a linear dependency of the size of the VM RAM size and time and required RAM for its analysis. 
- Start the VM **without KVM** (do not use ```--enable-kvm``` option) adding options ```-qmp tcp::6666,server -s```. These two options open a QMP server on ```localhost:6666``` and a GDB server on ```localhost:1234```.\
If you are running an INTEL machine you have to determine the MAX_PHY value of the emulated CPU (unfortunately this parameter is not exposed by QEMU...). To do it runs a Linux distribution with the same ```-cpu``` and ```-machine``` options of your VM without KVM and runs ```cat /proc/cpuinfo | grep "address sizes"```. MAX_PHY is equal to the ```bits physical``` value.\
On a different terminal session run ```qemu_elf_dumper.py 127.0.0.1:6666 127.0.0.1:1234 path_to_existing_output_folder```. If you are running an INTEL VM add the option ```-c CPUSpecifics:MAXPHYADDR:XXX``` where ```XXX``` is the value extracted previously. When you want to dump the VM press CTRL-C on ```qemu_elf_dumper.py``` terminal session: it stops the machine, dumps the physical memory and save information about the hardware on an ELF core file.
- Extract the pointers, strings other metadatas and perform static analysis on the ELF core dump using ```extract_features.py PATH_TO_DUMP/dump.elf EXISTING_PATH_TO_RESULTS/```. This script produces various ```extracted_XXX.lzma``` compressed pickle files used by the other moduli. This step can be very long due to the Ghidra static analysis phase.
- Extract the doubly linked lists using ```bdh_doubly_linked_lists.py --min_offset -PSI --max_offset PSI --offset_step ALPHA --min-size SIZE PATH_TO_RESULTS/extracted_ptrs.lzma PATH_TO_RESULTS/dll.lzma```. This step can be very long and consume a **HUGE** amount of RAM.
  - ```PSI``` is the maxium and minimum offset (positive and negative) from each pointer in which look for related pointers of a next-prev couple inside a list node. **MUST BE A POWER OF 2 AND MULTIPLE OF ALPHA**. The highest the value the greater the execution time, the ram required, and the number of results (including false positives). We have used 8192 for 64-bit OS and 4096 for 32-bit ones, for normal uses it can be possible to reduce them. See the [paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) for more details.
  - ```ALPHA``` is the pointer size used by the OS (8 for 64-bit CPUs, 4 for 32-bit ones).
  - ```SIZE``` is the minimum length of a doubly linked list. We used 3 as value in all our experiments. The lower the value the greater the execution time, the ram required, and the number of results (including false positives). See the [paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) for more details.
- (optional) Extract all the pointers chains using ```compute_chains.py --min_offset -PSI --max_offset PSI --offset_step ALPHA PATH_TO_RESULTS/extracted_ptrs.lzma CHAINS_DIR```. This script produces a compressed pickle file for each offset between [-PSI, PSI] in step of ALPHA containing all the pointer chains in Gamma graph offset. See the [paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) for more details.
- Extract all the binary trees with ```trees.py --min_offset -PSI_T --max_offset PSI_T --offset_step ALPHA PATH_TO_RESULTS/extracted_ptrs.lzma PATH_TO_RESULTS/trees.lzma```. ```PSI_T``` has the same meaning of ```PSI``` but it is used only to extract trees. **The number of results drammatically increase with the increase of this value!**  We have used 64 for 64-bit OSs and 32 for 32-bit OSs.  The highest the value the greater the execution time, the ram required, and the number of results (including false positives). See the [paper](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_s398_paper.pdf) for more details.
- Reorganize and filter structures using ```extract_structs.py -max_size PSI PATH_TO_RESULTS```. This script produce ```PATH_TO_RESULTS/results.lzma``` compressed pickle which can be explored using ```fossil.py```
- Explore the results with the interactive fossil shell ```fossil.py PATH_TO_RESULTS```
  Examples of fossil shell commands:
  - Look for a string in circular doubly linked lists: ```find_string -cdl bash```
  - Show all the strings in the same data structure at a fixed offset ```expand_struct -cdl 103 720```
  - Perform a zero knowledge search in circular doubly linked lists ```zero -cdl```

Each command accepts ```-h``` printing an help (also inside fossil interactive shell).

## Build and usage of Docker/Podman container
It is possible to build and use a Docker/Podman container containing the entire Fossil suite.
- Clone this repo and run ```podman build -t fossil .``` to build the container (it require some time). Here we use ```podman``` but the same exact commands are valid also on Docker.
- Inside the container, Fossil is located at ```/fossil``` and requires to bind a volume to ```/data``` which will contains input and output files consumed/produced. The container has Ghidra 10.3.2 already installed. If you want to use a different Ghidra version, put it in the binded ```/data``` volume on the host, and add the option ```-e GHIDRA_PATH=/data/GHIDRA_INSTALL_DIR/```.
- To call a Fossil script ```podman run --network="host" --rm --it --volume HOST_PATH_TO_DATA:/data:Z localhost/fossil:latest /fossil/COMMAND OPTIONS```
  - For example, to run ```bdh_doubly_linked_lists.py``` having data inside ```/home/andrea/dumps``` on the host: ```podman run --network="host" --rm --it --volume /home/andrea/dumps:/data:Z localhost/fossil:latest /fossil/bdh_doubly_linked_lists.py --min_offset -8192 --max_offset 8192 --offset_step 8 --min-size 3 /data/extracted_ptrs.lzma /data/dll.lzma```
- To run ```qemu_elf_dumper.py```, run ```qemu``` on the host machine and call ```qemu_elf_dumper.py``` inside the container with an extra option: if the binded host path is ```HOST_PATH_TO_DATA``` add ```-d HOST_PATH_TO_DATA``` option to the command line.
