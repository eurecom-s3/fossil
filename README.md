# fossil
OS-agnostic tool for data structures recovery

It requires Ghidra 10.1.2

From a memory dump in ELF format dump.elf:
- ```./fossil/extract_features.py dump.elf output```
- ```./fossil/bdh_doubly_linked_lists.py --min_offset -8192 --max_offset 8192 --offset_step 8 --min-size 3 output/extracted_ptrs.lzma output/dll.lzma```
- ```./fossil/compute_chains.py --min_offset -8192 --max_offset 8192 --offset_step 8 output/extracted_ptrs.lzma output/chains```
- ```./fossil/trees.py --min_offset -64 --max_offset 64 --offset_step 8 output/extracted_ptrs.lzma output/trees.lzma```
- ```./fossil/extract_structs.py -max_size 8192 ./output```
- ```./fossil/fossil.py output```


In fossil shell:
- Look for a string in circular doubly linked lists: ```find_string -cdl bash```
- Show all the strings in the same data structure at a fixed offset ```expand_struct -cdl 103 720```
- Perform a zero knowledge search in circular doubly linked lists ```zero -cdl```

Each command accepts ```-h```  and print an help
