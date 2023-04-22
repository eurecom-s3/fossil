import numpy as np
from tqdm import tqdm
import matplotlib.pylab as plt
import seaborn as snb
import logging
from statistics import mode
from collections import Counter, defaultdict
from bisect import bisect_left

class StructureShapeFinder:
    def __init__(self, ptrs, v2o, bitmap, align, max_size, debug=False):
        self.ptrs = ptrs         # Pointers mapping
        self.v2o = v2o           # Traslator for virtual addresses-to-in file offset 
        self.btm = bitmap        # Bitmap for 0 values
        self.align = align       # Architecture alignment
        self.max_size = max_size # Maximum size for a struct
        self.debug = debug       # If true print statistics and plots
        self.ptrs_keys = sorted(self.ptrs.keys())

    def _is_null(self, addr):
        """Verify if an address contains all null bytes"""
        # !!!WARNING!!! this implementation suppose only aligned addresses!
        offset = self.v2o[addr]
        if offset == -1:
            raise ValueError

        return not self.btm[offset:offset+self.align].any()
    
    def _generate_heatmap(self, ptrs_list, window):
        # heatmap[elemento_lista, offset]
        # -1 data, 0 null, 1 ptr
        # TODO: speedup and limits size in cases where the virtual addresses are not in RAM
        offset_range = range(-window+self.align, window, self.align)
        heatmap = np.zeros(shape=(len(ptrs_list),len(offset_range)), dtype=np.int8)

        for offset_id, offset in enumerate(tqdm(offset_range, disable=not self.debug)):
            counter = 0
            null_counter = 0
            for elem_id, elem_base in enumerate(ptrs_list):
                elem_base = int(elem_base) # Numpy uint64 :/
                if elem_base + offset in self.ptrs:
                    counter += 1
                    heatmap[elem_id,offset_id] = 1
                    continue
                try:
                    if self._is_null(elem_base + offset):
                        null_counter += 1
                        continue
                except ValueError as e:
                    logging.debug(f"MISSING ADDRESS (?) element {elem_id} offset {offset}")
                    continue

                heatmap[elem_id,offset_id] = -1
        return heatmap
    
    
    def _tri_distance(self, v):
        """Calculate triangle distance not normalized"""
        # Normalization = len(list_pointers)**2 / 3
        _, count = np.unique(v, return_counts=True)
        if len(count) == 3:
            a, b, c = count
            return a * (b + c) + b * c
        elif len(count) == 2:
            a, b = count
            return a * b
        else:
            return 0
    
    def _determine_aligment(self, heatmap, struct_size):
        """Determine the alignment of the maximum size window containing the structure"""
        # The technique is based on the fact that at the same offset all (but 2) structures
        # should have value of the same type (null, pointers or data) (WARNING! this could be false
        # in the case of unions and unaligned structures!) In reality, we are not able to perfectly distinguish between 
        # pointers and data values: a pointer value could be a false positive, however we cannot have false
        # negatives. We construct a metric (the triangular metric) which is maximum when the elements of all the
        # structures at a same offset are equally distributed between pointer, null and data classes. 
        # We assume that the sum of the metric for each offset in the window should have a minimum when the correct
        # alignment is found
        
        # Calculate puntual triangular sum
        triangular_measures = np.apply_along_axis(self._tri_distance, 0, heatmap)

        # Perform a sliding sum
        total_windows = struct_size // self.align
        zero_idx = total_windows - 1
        triangular_sum = np.zeros(total_windows, dtype=np.float64)
        
        triangular_sum[0] = np.sum(triangular_measures[:zero_idx + 1])
        for i in range(1, zero_idx+1):
            triangular_sum[i] = triangular_sum[i-1] - triangular_measures[i-1] + triangular_measures[zero_idx+i]
        
        # Determine s- and s+
        # In theory is possible to have multiple consegutive minimums, we take the first one because we are unable
        # to say which one is the correct
        s_minus = -struct_size + self.align +  triangular_sum.argmin() * self.align 
        s_plus = s_minus + struct_size - self.align
        
        if self.debug:
            fig, ax = plt.subplots()
            ax.plot(np.arange(-struct_size + self.align, self.align, self.align), triangular_sum)
            ax.axvline(x=s_minus, color="r")
            try:
                plt.show()
            except ValueError:
                print("Math domain error")
        return s_minus, s_plus
    
    def _fit_knee_model(self, xa, ya):
        """Supposing the function is decomposable in two segments, fit the data and return the error"""

        model_line = lambda x,x0,y0,x1,y1: ((y1 - y0)/(x1 - x0))*(x - x0) + y0
        errors = np.empty(len(xa), dtype=np.float64)

        for i in range(1,len(xa)-1):
            e1 = np.sum(np.power(ya[:i+1] - model_line(xa[:i+1], xa[0], ya[0], xa[i], ya[i]), 2))
            e2 = np.sum(np.power(ya[i:] - model_line(xa[i:], xa[i], ya[i], xa[-1], ya[-1]), 2))
            errors[i] = e1/i + e2/(len(xa)-i) # Weighted mean
        errors[0] = errors[1]   # First point is undefined
        errors[-1] = errors[-2] # Last point is undefined

        return errors


    def _determine_maximum_extensions(self, heatmap):
        """Determine the maximum extension of the structure at its 'left' and 'right'"""
        #  ~WORK!
        # TODO: document me :)
        
        # Divide positive offset from negative ones
        total_windows = self.max_size // self.align
        zero_idx = total_windows - 1
        p_heatmap = heatmap[:,zero_idx:]
        n_heatmap = np.flip(heatmap[:,:zero_idx+1],1)
        ptr_counter = lambda x: np.count_nonzero(x == 1)
        
        x = np.arange(zero_idx, dtype=np.float64) * self.align
        lx = x.copy()
        lx[0] = 1 # Workaround for log
        lx = np.log(lx)
        sizes = []
        
        # Calculate ratio measure for each side of the structure
        for heatm in [n_heatmap, p_heatmap]:
            ptrs_counters = np.apply_along_axis(ptr_counter, 0, heatm) # Count how much pointers there are at a fixed offset
            ratio_measure = np.zeros(zero_idx, dtype=np.float64)
            total_valid_ptrs = 0 # Total number of pointers in a window of size i which are "pointers" for all the structures
            total_ptrs = 0 # Total pointers in a window of size i
            threshold = heatm.shape[0] - 2 # We assume that a maximum of two structures do not respect the rule (Head and Tail in a list)
            
            for i in range(zero_idx):
                if ptrs_counters[i]: # There is at least a pointer!
                    t = ptrs_counters[i]
                    if t >= threshold:
                        total_valid_ptrs += t
                    total_ptrs += t

                try:
                    ratio_measure[i] = total_valid_ptrs/total_ptrs
                except ZeroDivisionError:
                    ratio_measure[i] = 0
             
            # Fit log-log data with a knee-function
            # The knee position which generates the minimum error is assumed to be
            # the correct knee
            ly = np.log(ratio_measure)
            errors = self._fit_knee_model(lx, ly)
            knee_pos = errors.argmin()
            sizes.append(x[knee_pos])
            
            if self.debug:
                plt.loglog(x, ratio_measure)
                plt.axvline(x=sizes[-1], ymin=0, ymax=1, color="r")
                try:
                    plt.show()
                
                    plt.loglog(x, errors)
                    plt.show()
                except ValueError:
                    print("Math domain error")
        sizes[0] = -sizes[0]
        return sizes
    
    
    def shape_complex(self, ptrs_list, limits=tuple()):
        """Given a collection of addresses (inside) structures try to determine the shape of the structures containing them"""
                
        # Calculate the minimum distance MIN between two consecutive pointers in the list:
        # if it is < max_size we suppose that it is the structure total size and we look for
        # the "aligment" of the window of size MIN. Otherwise, we try to find the the maximum extensions
        # of the structure on "the right" and "the left" side
        minimum_difference = np.diff(np.sort(ptrs_list)).min()
        struct_size = int(min(minimum_difference, self.max_size))

        # Generate a "heatmap" which maps for each single pointer of the list and for each offset in the max structure size
        # if it is a pointer, a null value or a data value
        heatmap = self._generate_heatmap(ptrs_list, struct_size)

        if struct_size == minimum_difference:
            if self.debug:
                print("Use alignment...")
            s_minus, s_plus = self._determine_aligment(heatmap, struct_size)
        else:
            if self.debug:
                print("Use maximum extension...")
            s_minus, s_plus = self._determine_maximum_extensions(heatmap)
        
        if self.debug:
            print(f"Structure size: {struct_size}")
            ax = snb.heatmap(heatmap, cmap="Blues", xticklabels=[])
            ax.vlines([(s_minus + struct_size)//self.align, (s_plus + struct_size)//self.align], *ax.get_ylim(), linewidth=4, color="r")
            ax.vlines([struct_size//self.align], *ax.get_ylim(), linewidth=4, color="g")
            ax.plot()

        if limits: # Impose restrictions if some limits are passed
            lm, lp = limits
            if s_plus < lp:
                s_plus = lp
            if s_minus > lm:
                s_minus = lm
    
        return s_minus, s_plus, None
   
    def shape(self, ptrs_list, limits=tuple()):
        """Given a collection of addresses inside structures try to determine the shape of the structures using only pointers"""

        elems = sorted(ptrs_list)
        max_offset = min(self.max_size, int(mode(np.diff(np.array(elems, dtype=np.uint64)))))
        visited_ptrs = defaultdict(list)

        # Find all offset containing pointers near to the pointer inside the structures
        counter = []
        for elem in elems:
            min_idx = bisect_left(self.ptrs_keys, elem)
            for idx in range(min_idx, len(self.ptrs_keys)):
                diff = self.ptrs_keys[idx] - elem
                if diff > max_offset:
                    break
                counter.append(diff)
                visited_ptrs[diff].append(self.ptrs_keys[idx])

        # Consider only offset containg at least 90% of valid pointers
        most_populated = [(offset, count) for offset,count in Counter(counter).most_common() if count >= 0.9 * len(elems)]

        # Check if the remaining 10% is populated by NULL pointers
        null_counter = []
        for elem in elems:
            for offset, count in most_populated:
                if count == len(elems):
                    continue
                
                if (off := self.v2o[elem + offset]) == -1:
                    continue

                try:
                    if not self.btm[off:off+align].any():
                        null_counter.append(offset)
                except:
                    pass

        # Consider only offset containing at least len(elems) - 1 null or pointers (one is special, the HEAD)
        counter.extend(null_counter)
        offsets = [(offset, count) for offset,count in Counter(counter).most_common() if count >= len(elems) - 1]
        offsets.sort()
        off_ptrs = {offset:set(visited_ptrs[offset]) for offset, _ in offsets} 

        if len(offsets) == 0:
            return -max_offset, max_offset, off_ptrs
        if len(offsets) == 1:
            if offsets[0][0] > 0:
                return -max_offset, offsets[0][0], off_ptrs
            else:
                return offsets[0][0], max_offset, off_ptrs

        if offsets[0][0] > 0:
            m = -max_offset
        else:
            m = offsets[0][0]

        if offsets[-1][0] < 0:
            p = max_offset
        else:
            p = offsets[-1][0]

        return m, p, off_ptrs

