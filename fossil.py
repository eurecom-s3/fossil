#!/usr/bin/env python3

from copy import deepcopy
from cmd2 import Cmd, with_category, with_argparser, style, fg, bg
import argparse
import sys
from more_itertools import circular_shifts
from prettytable import PrettyTable
from compress_pickle import load as load_c
from itertools import chain
from binarytree import build as buildtree
from statistics import mean, StatisticsError
from collections import Counter, defaultdict
import textwrap


finder_parser = argparse.ArgumentParser()
finder_parser.add_argument("-i", "--include", action="store_true", help="Look for strings include this substring", default=False)
finder_parser.add_argument("-I", "--insensitive", action="store_true", help="Case insensitive", default=False)
finder_parser.add_argument("-cdl", "--circular_double_linked", action="store_true", help="Look for strings in Circular Double Linked lists", default=False)
finder_parser.add_argument("-ldl", "--linear_double_linked", action="store_true", help="Look for strings in Linear Double Linked lists", default=False)
finder_parser.add_argument("-t", "--trees", action="store_true", help="Look for strings in double trees", default=False)
finder_parser.add_argument("-a", "--arrays", action="store_true", help="Look for strings in arrays", default=False)
finder_parser.add_argument("-as", "--arrays_struct", action="store_true", help="Look for strings in arrays of structs", default=False)
finder_parser.add_argument("-ds", "--derived_structs", action="store_true", help="Look for strings in derived structs", default=False)
finder_parser.add_argument("-l", "--lists", action="store_true", help="Look for strings in linked lists", default=False)
finder_parser.add_argument("-r", "--referenced", action="store_true", help="Only referenced", default=False)
finder_parser.add_argument("string", nargs='+', default=[], help="Strings to look for")

expand_parser = argparse.ArgumentParser()
expand_parser.add_argument("-cdl", "--circular_double_linked", action="store_true", help="Expand Circular Double Linked lists", default=False)
expand_parser.add_argument("-ldl", "--linear_double_linked", action="store_true", help="Expand in Linear Double Linked lists", default=False)
expand_parser.add_argument("-t", "--trees", action="store_true", help="Expand in double trees", default=False)
expand_parser.add_argument("-a", "--arrays", action="store_true", help="Expand in arrays", default=False)
expand_parser.add_argument("-as", "--arrays_struct", action="store_true", help="Expand arrays of structs", default=False)
expand_parser.add_argument("-ds", "--derived_structs", action="store_true", help="Look for strings in derived structs", default=False)
expand_parser.add_argument("-l", "--lists", action="store_true", help="Expand simple list", default=False)
expand_parser.add_argument("-p", "--pointed", action="store_true", help="String is pointed")
expand_parser.add_argument("index", type=int, help="Structure index")
expand_parser.add_argument("offset", type=int, help="Offset in structure")

zero_parser = argparse.ArgumentParser()
zero_parser.add_argument("-cdl", "--circular_double_linked", action="store_true", help="Look for strings in Circular Double Linked lists", default=False)
zero_parser.add_argument("-ldl", "--linear_double_linked", action="store_true", help="Look for strings in Linear Double Linked lists", default=False)
zero_parser.add_argument("-t", "--trees", action="store_true", help="Look for strings in double trees", default=False)
zero_parser.add_argument("-as", "--arrays_struct", action="store_true", help="Look for strings in arrays of structs", default=False)
zero_parser.add_argument("-ds", "--derived_structs", action="store_true", help="Look for strings in derived structs", default=False)
zero_parser.add_argument("-l", "--lists", action="store_true", help="Look for strings in linked lists", default=False)
zero_parser.add_argument("-r", "--referenced", action="store_true", help="Only referenced", default=False)


class FossilShell(Cmd):
    def __init__(self, path):
        dinosaur = "\n\
            :ymMMmy/`\n\
            /MMMMMMMMNy/`                                                                     ```\n\
            -NMMMMMMMMMMMms-                                                       `-/+oydNNNNMMMMNmdy/.\n\
            :hMMMMMMMMMMMMMNo-`                                               ./smMMMMMMMMMMMMMMMMMMMMMmo`\n\
            :NMMMMMMMMMMMMMMMdo`                                          /hMMMMMMMMMMMMMmys+////+ohmMMNo\n\
                :mMMMMMMMMMMMMMMMMN:                                       +mMMMMMMMMMMNy+:`            `:+/\n\
                .:yMMMMMMMMMMMMMMM/                                    :mMMMMMMMMMdo-\n\
                    omMMMMMMMMMMMMMN/                                  sMMMMMMMMMh-\n\
                    +mMMMMMMMMMMMMM:                               `yMMMMMMMMm-\n\
                        oMMMMMMMMMMMMMh                              -dMMMMMMMMm.\n\
                `+ydmmMMMMMMMMMMMMMMMN`                           `sMMMMMMMMMN.\n\
            -yNMMMMMMMMMMMMMMMMMMMMN                          .sNMMMMMMMMMM/\n\
        `-hyydNMMMMMMMMMMMMMMMMMMMMMMMm                        -yMMMMMMMMMMMMy\n\
        NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN                 ./oyhdmMMMMMMMMMMMMMM:\n\
        -hmmmmdyo+/:::::+dMMMMMMMMMMMMm          `` .ohNMMMMMMMMMMMMMMMMMMMM+\n\
                        :NMMMMMMMMMMd  `/ydNNMMMMNMMMMMMMMMMMMMMMMMMMMMMMy\n\
                /+//.      oMMMMMMMMMMMmdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm`\n\
            ``.:mMMo     `mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd\n\
            odNMMdyMMMy`    :MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN`\n\
            .odMMMMMMMMd`    hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN`\n\
        `hdNMds+odMMMMd`   .mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-\n\
                `yMMMMd`   -mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM.\n\
                    `:oNMm+:. `sMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm\n\
                        .hNMMMNhosMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM+\n\
                        -hNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd`\n\
                            :oydNMMhodMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd`\n\
                            -syysso+-`  `.sMMMMMMMMMMMMMMMMMMMMMMMMMMMm.\n\
                        -dNMMNMMMMMMMNmhmMMMMMMMMMh`.-:/+o+NMMMMMMMMMMmo`\n\
                        .. `+smMMMMMMMMNddddMMMMMMM-       dMMMMMMMMMMMMNm-\n\
                            /mMMNsmMMy++-`    :dMMMMMs        sNMMMMMMMMMMMMm`\n\
                            :No-.`dMM:           +NMMMN-        `-++:-:/+sdMMMd\n\
                                /Mm+             +MMMMs                   hMMM+\n\
                                sh`            `sMMMNs`                   +MMMm\n\
                                        -oo/./mMMMy.                 :hdhhMMMh\n\
                                        yNmMMMMMMMo                  .NhdMMMMM/\n\
                                        `:yNMMMMN+                       :MMMMs\n\
                                    :shNMMMMMMM+                      .yNMMMMM.\n\
                                `sNMMMMMMMNNmh`                     :NMNNNMMd`\n\
                                yNdyyso:.`                          ./`   :-\n\
\t\t\t\t\t  ______                _  _ \n\
\t\t\t\t\t |  ____|              (_)| |\n\
\t\t\t\t\t | |__  ___   ___  ___  _ | |\n\
\t\t\t\t\t |  __|/ _ \ / __|/ __|| || |\n\
\t\t\t\t\t | |  | (_) |\__ \\\\__ \| || |\n\
\t\t\t\t\t |_|   \___/ |___/|___/|_||_|\n\
                             \n\
                             "
        Cmd.__init__(self, use_ipython=True)
        self.self_in_py = True
        # self.intro = style(dinosaur, bold=True)#, fg=fg.black, bg=bg.white)
        self.prompt = 'fossil> '
        self.fossil = None

        # Hide default settings
        # self.remove_settable('debug')
        self.path = path

        # Load results, strings, ptrs, rptrs
        self.results = load_c(path + "/results.lzma")
        self.strs = load_c(path + "/extracted_strs.lzma")
        self.ptrs = load_c(path + "/extracted_ptrs.lzma")
        self.rptrs = load_c(path + "/extracted_rptrs.lzma")

# (str(datetime.fromtimestamp(candidate/10**9))

    def look_into(self, valid_strings_addrs, structs_name, level, name, referenced, table):
        try:
            if level == -1:
                res = self.results[structs_name]
            else:
                res = self.results["derived"][structs_name][level]
        except KeyError as e:
            print(e)
            return 0

        rows = 0
        for idx, cicle in enumerate(res):
                for offset, addrs in cicle.embedded_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                        if not referenced or (referenced and (cicle.referenced if level == -1 else cicle.parent.referenced)):
                            found.extend(i)
                    else:
                        rows += len(found)
                        for i in found:
                            table.add_row([name, idx, cicle.referenced, "X", offset, self.strs[i], hex(i)])

                for offset, addrs in cicle.pointed_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                        if not referenced or (referenced and (cicle.referenced if level == -1 else cicle.parent.referenced)):
                            found.extend(i)
                    else:
                        rows += len(found)
                        for i in found:
                            table.add_row([name, idx, cicle.referenced if level == -1 else cicle.parent.referenced, "", offset, self.strs[i], hex(i)])
        return rows

    @with_argparser(finder_parser)
    @with_category("Operational commands")
    def do_find_string(self, args):
        """Find structures referring specific strings"""
        table = PrettyTable()
        table.field_names=["Struct type", "Index", "Referenced", "Embedded", "Offset", "String", "String address"]
        rows = 0

        if args.insensitive:
            ss = [x.lower() for x in args.string]
            if args.include:
                valid_strings_addrs = [{x for x,y in self.strs.items() if s in y.lower()} for s in ss]
            else:
                valid_strings_addrs = [{x for x,y in self.strs.items() if s == y.lower()} for s in ss]
        else:
            ss = args.string
            if args.include:
                valid_strings_addrs = [{x for x,y in self.strs.items() if s in y} for s in ss]
            else:
                valid_strings_addrs = [{x for x,y in self.strs.items() if s == y} for s in ss]

        if args.derived_structs:
            level = 0
        else:
            level = -1

        if args.circular_double_linked:
            rows += self.look_into(valid_strings_addrs, "cicles", level, "Circular Double Linked", args.referenced, table)
            
        if args.linear_double_linked:
            rows += self.look_into(valid_strings_addrs, "linears", level, "Linear Double Linked", args.referenced, table)

        if args.trees:
           rows += self.look_into(valid_strings_addrs, "trees", level, "Trees", args.referenced, table)
        
        if args.lists:
           rows += self.look_into(valid_strings_addrs, "lists", level, "Linked lists", args.referenced, table)
        
        if args.arrays and not args.derived_structs:
            for idx, cicle in enumerate(self.results["arrays_strings"]):
                found = []
                for valid_strings_addr in valid_strings_addrs:
                    if not (i := valid_strings_addr.intersection(cicle.strs_array)):
                        break
                    if not args.referenced or (args.referenced and cicle.referenced):
                        found.extend(i)
                else:
                    rows += len(found)
                    for i in found:
                        table.add_row(["Array of *strings", idx, cicle.referenced, "", 0, self.strs[i], hex(i)])

        if args.arrays_struct and not args.derived_structs:
            if args.derived_structs:
                rows += self.look_into(valid_strings_addrs, "arrays", 0, "Arrays of *struct", args.referenced, table)
            else:
                res = self.results["arrays"]
                for idx, cicle in enumerate(res):
                    if not cicle.structs:
                        continue
                    for offset, addrs in cicle.structs.embedded_strs.items():
                        found = []
                        for valid_strings_addr in valid_strings_addrs:
                            if not (i := valid_strings_addr.intersection(addrs)):
                                break
                            if not args.referenced or (args.referenced and cicle.referenced):
                                found.extend(i)
                        else:
                            rows += len(found)
                            for i in found:
                                table.add_row(["Array of *structs", idx, cicle.referenced, "X", offset, self.strs[i], hex(i)])

                    for offset, addrs in cicle.structs.pointed_strs.items():
                        found = []
                        for valid_strings_addr in valid_strings_addrs:
                            if not (i := valid_strings_addr.intersection(addrs)):
                                break
                            if not args.referenced or (args.referenced and cicle.referenced):
                                found.extend(i)
                        else:
                            rows += len(found)
                            for i in found:
                                table.add_row(["Array of *structs", idx, cicle.referenced, "", offset, self.strs[i], hex(i)])
        
        

        table.sortby = "Referenced"
        table.reversesort = True
        print(f"Results: {rows}")
        self.ppaged(table)

    def expander(self, t, level, index, offset, pointed, table):
        if level == -1:
            res = self.results[t][index]
        else:
            res = self.results["derived"][t][level][index]

        if pointed:
            for addr in res.pointed_strs[offset]:
                if addr in self.strs:
                    table.add_row([f"{hex(addr - offset)}", self.strs[addr]])
        else:
            for addr in res.embedded_strs[offset]:
                if addr in self.strs:
                    table.add_row([f"{hex(addr - offset)}", self.strs[addr]])

    @with_argparser(expand_parser)
    @with_category("Operational commands")
    def do_expand_struct(self, args):
        """Expand structure at fixed offset"""
        table = PrettyTable()
        table.field_names=["Address", "String"]

        index = args.index
        offset = args.offset

        if args.derived_structs:
            level = 0
        else:
            level = -1

        if args.trees:
            if level == -1:
                if args.pointed:
                    # Accrocchio
                    t = []
                    for ptr in self.results["trees"][index].nodes:
                        try:
                            if ptr and self.ptrs[ptr + offset] in self.results["trees"][index].pointed_strs[offset]:
                                t.append(self.strs[self.ptrs[ptr + offset]])
                            else:
                                t.append(" ")
                        except Exception as e:
                            t.append(" ")

                    print(buildtree(t))

                else:
                    try:
                        t = [self.strs[x] if x else "" for x in self.results["trees"][index].get_tree_embedded_strs(offset)]
                        print(buildtree(t))
                    except Exception as e:
                        pass
                return
            else:
                self.expander("trees",level,index,offset,args.pointed,table)

        if args.circular_double_linked:
            self.expander("cicles",level,index,offset,args.pointed,table)

        if args.linear_double_linked:
             self.expander("linears",level,index,offset,args.pointed,table)

        if args.arrays:
            for addr in self.results["arrays_strings"][index].strs_array:
                table.add_row([f"{hex(addr - offset)}", self.strs[addr]])

        if args.arrays_struct:
            if level == -1:
                if not self.results["arrays"][index].structs:
                    self.ppaged(table)
                    return
                
                if args.pointed:
                    for addr in self.results["arrays"][index].structs.pointed_strs[offset]:
                        table.add_row([f"{hex(addr - offset)}", self.strs[addr]])
                else:
                    for addr in self.results["arrays"][index].structs.embedded_strs[offset]:
                        table.add_row([f"{hex(addr - offset)}", self.strs[addr]])
            else:
                self.expander("arrays",level,index,offset,args.pointed,table)

        if args.lists:
             self.expander("lists",level,index,offset,args.pointed,table)

        table.sortby = "Address"
        self.ppaged(table)

        r = []
        for row in table:
            row.border = False
            row.header = False
            r.append(row.get_string(fields=["String"]).strip())
        print(r)

    def find_string_paper(self, names, referenced):
        res = {}
        for name in names:
            rows = 0

            valid_strings_addrs = [{x for x,y in self.strs.items() if name == y}]

            for idx, cicle in enumerate(self.results["cicles"]):
                if referenced and not cicle.referenced:
                    continue
                for offset, addrs in cicle.embedded_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break                        
                    else:
                        rows += 1

                for offset, addrs in cicle.pointed_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                        
            for idx, cicle in enumerate(self.results["linears"]):
                if referenced and not cicle.referenced:
                    continue
                for offset, addrs in cicle.embedded_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                    
                for offset, addrs in cicle.pointed_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                    

        # if args.derived_structs:
        #     for idx, cicle in enumerate(self.results["derived"]):
        #         for offset, addrs in cicle.embedded_strs.items():
        #             found = []
        #             for valid_strings_addr in valid_strings_addrs:
        #                 if not (i := valid_strings_addr.intersection(addrs)):
        #                     break
        #                 if not args.referenced or (args.referenced and cicle.referenced):
        #                     found.extend(i)
        #             else:
        #                 rows += len(found)
        #                 for i in found:
        #                     table.add_row(["Derived", idx, cicle.referenced, "X", offset, self.strs[i]])

        #         for offset, addrs in cicle.pointed_strs.items():
        #             found = []
        #             for valid_strings_addr in valid_strings_addrs:
        #                 if not (i := valid_strings_addr.intersection(addrs)):
        #                     break
        #                 if not args.referenced or (args.referenced and cicle.referenced):
        #                     found.extend(i)
        #             else:
        #                 rows += len(found)
        #                 for i in found:
        #                     table.add_row(["Derived", idx, cicle.referenced, "", offset, self.strs[i]])

            for idx, cicle in enumerate(self.results["trees"]):
                if referenced and not cicle.referenced:
                    continue
                for offset, addrs in cicle.embedded_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                        

                for offset, addrs in cicle.pointed_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                    
        
            for idx, cicle in enumerate(self.results["arrays_strings"]):
                if referenced and not cicle.referenced:
                    continue
                found = []
                for valid_strings_addr in valid_strings_addrs:
                    if not (i := valid_strings_addr.intersection(cicle.strs_array)):
                        break
                    else:
                        rows += 1
                    

            for idx, cicle in enumerate(self.results["arrays"]):
                if referenced and not cicle.referenced:
                    continue
                if not cicle.structs:
                    continue
                for offset, addrs in cicle.structs.embedded_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += len(found)
                        

                for offset, addrs in cicle.structs.pointed_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                        
        
            for idx, cicle in enumerate(self.results["lists"]):
                if referenced and not cicle.referenced:
                    continue
                for offset, addrs in cicle.embedded_strs.items():
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1
                        

                for offset, addrs in cicle.pointed_strs.items():
                    if referenced and not cicle.referenced:
                        continue
                    found = []
                    for valid_strings_addr in valid_strings_addrs:
                        if not (i := valid_strings_addr.intersection(addrs)):
                            break
                    else:
                        rows += 1

            res[name] = rows
        print(f"Results: {sorted(res.items(), key=lambda x: x[1], reverse=True)}")

    def discard_offsets(self, x):
        k = list(x.embedded_strs.keys())
        for i in k:
            s = [self.strs[j] for j in x.embedded_strs[i]]
            if len(Counter(s)) < 0.5 * len(x.embedded_strs[i]) or len(set(s)) == 1:
                x.embedded_strs.pop(i)
        
        k = list(x.pointed_strs.keys())
        for i in k:
            s = [self.strs[j] for j in x.pointed_strs[i]]
            if len(Counter(s)) < 0.5 * len(x.pointed_strs[i]) or len(set(s)) == 1:
                x.pointed_strs.pop(i)


    def filter_zero(self, data, level, referenced):

        if level == -1:
            cic = self.results[data]
        else:
            cic = self.results["derived"][data][level]
        strs = self.strs

        if data == "arrays":
            cic = [x.structs for x in cic]

        for x in cic:
            self.discard_offsets(x) # Discard offsets with all equal strings or if there are less than half different strings
        cic = [x for x in cic if x.embedded_strs or x.pointed_strs] # Consider only with strings 
        cic = [x for x in cic if any([len(k) >= min(0.8 * len(x), len(x)-1) for k in x.embedded_strs.values()]) or any([len(k) >= min(0.8 * len(x), len(x)-1) for k in x.pointed_strs.values()])] # Consider only struct with offset with a minium of 80% of strings
        if referenced:
            cic = [x for x in cic if x.referenced]
        
        strs_freq = defaultdict(list) # Collect how much a string is present
        for idx, i in enumerate(cic):
            for j in i.embedded_strs.values():
                for k in j:
                    s = self.strs[k]
                    strs_freq[s].append(idx)
            for j in i.pointed_strs.values():
                for k in j:
                    s = self.strs[k]
                    strs_freq[s].append(idx)
        
        def order_by_str_mean(x):
            m = []
            for j in x.embedded_strs.values():
                for k in j:
                    s = strs[k]
                    m.append(len(strs_freq[s]))
            for j in x.pointed_strs.values():
                for k in j:
                    s = strs[k]
                    m.append(len(strs_freq[s]))
            
            try:
                r = mean(m)
            except StatisticsError:
                r = 0
            return r
        
        cic.sort(key=order_by_str_mean) # Riordina con stringhe piu rare in alto
        return(cic)


    @with_argparser(zero_parser)
    @with_category("Operational commands")
    def do_zero(self, args):
        """Zero knowledge"""

        if args.derived_structs:
            level = 0
        else:
            level = -1

        if args.circular_double_linked:
            res = self.filter_zero("cicles", level, args.referenced)
            
        if args.linear_double_linked:
           res = self.filter_zero("linears", level, args.referenced)

        if args.trees:
           res = self.filter_zero("trees", level,  args.referenced)
        
        if args.lists:
           res = self.filter_zero("lists", level, args.referenced)
        
        if args.arrays_struct and not args.derived_structs:
            if args.derived_structs:
                res = self.filter_zero("arrays", 0, args.referenced)
            else:
                res = self.filter_zero("arrays", -1, args.referenced)
        
        for idx, i in enumerate(res):

            preferredWidth = 70*3
            wrapper = textwrap.TextWrapper(initial_indent=str(idx), width=preferredWidth,
                                        subsequent_indent=' '* len(str(idx)))
            for j in i.embedded_strs.values():
                message = [self.strs[k] for k in j] 
                print(wrapper.fill(str(message)))
            
            for j in i.pointed_strs.values():
                message = [self.strs[k] for k in j] 
                print(wrapper.fill(str(message)))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('workdir', type=str, help='Directory containing ')

    args = parser.parse_args()

    s = FossilShell(args.workdir)
    sys.exit(s.cmdloop())
