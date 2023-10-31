from bisect import bisect

class IntervalsMappingSimple:
    """
    Fast search in intervals 
    (begin) (end)
    """
    keys: tuple[int, ...]
    values: tuple[int, ...]

    def __init__(self, keys:tuple[int,...], values:tuple[int,...]) -> None:
        self.keys = keys
        self.values = values

    def __getitem__(self, element:int) -> int:
        index = bisect(self.keys, element) - 1
        begin = self.keys[index]
        if begin <= element < self.values[index]:
            return element - begin
        else:
            return -1

    def contains(self, element:int, size:int) -> int:
        index = bisect(self.keys, element) - 1
        begin = self.keys[index]
        end = self.values[index]
        if not(begin <= element < end) or element + size >= end:
            return -1
        else:
            return element - begin

    def get_values(self) -> zip:
        return zip(self.keys, self.values)

    def get_extremes(self) -> tuple[int, int]:
        return self.keys[0], self.values[-1]

class IntervalsMappingOffsets:
    """
    Fast search in intervals 
    (begin), (end, associated offset)
    """
    keys: tuple[int, ...]
    values: tuple[tuple[int, int], ...]

    def __init__(self, keys:tuple[int, ...], values:tuple[tuple[int,int], ...]) -> None:
        self.keys = keys
        self.values = values

    def __getitem__(self, element:int) -> int:
        index = bisect(self.keys, element) - 1
        begin = self.keys[index]
        end, data = self.values[index]
        if begin <= element < end:
            return element - begin + data
        else:
            return -1

    def contains(self, element:int, size:int) -> tuple[int, list[tuple[int,int,int]]]:
        """
        Return the maximum size and the list of intervals
        """
        index = bisect(self.keys, element) - 1
        begin = self.keys[index]
        end, data = self.values[index]
        if not(begin <= element < end):
            return 0, []

        intervals = [(element, min(end - element, size), element - begin + data)]
        if end - element >= size:
            return size, intervals

        # The address space requested is bigger than a single interval
        start = end
        remaining = size - (end - element)
        index += 1
        print(start, remaining, index)

        while index < len(self.values):
            begin = self.keys[index]
            end, data = self.values[index]
            
            # Virtual addresses must be contiguous
            if begin != start:
                return size - remaining, intervals
            
            interval_size = min(end - begin, remaining)
            intervals.append((start, interval_size, data))
            remaining -= interval_size
            if not remaining:
                return size, intervals
            start += interval_size
            index += 1
        return size, intervals

    def get_values(self) -> zip:
        return zip(self.keys, self.values)

    def get_extremes(self) -> tuple[int, int]:
        return self.keys[0], self.values[-1][0]

class IntervalsMappingData:
    """
    Fast search in intervals 
    (begin), (end, associated data)
    """
    keys: tuple[int, ...]
    values: tuple[tuple[int, tuple[int, int, int]], ...]

    def __init__(
        self, 
        keys:tuple[int, ...], 
        values:tuple[tuple[int, tuple[int, int, int]], ...]
    ) -> None:
        self.keys = keys
        self.values = values

    def __getitem__(self, element:int) -> int|tuple[int, int, int]:
        index = bisect(self.keys, element) - 1
        begin = self.keys[index]
        end, data = self.values[index]
        if begin <= element < end:
            return data
        else:
            return -1

    def contains(self, element:int, size:int) -> int|tuple[int, int, int]:
        index = bisect(self.keys, element) - 1
        begin = self.keys[index]
        end, data = self.values[index]
        if not(begin <= element < end) or element + size >= end:
            return -1
        else:
            return data

    def get_values(self) -> zip:
        return zip(self.keys, self.values)

    def get_extremes(self) -> tuple[int, int]:
        return self.keys[0], self.values[-1][0]

class IntervalsMappingOverlapping: 
    """
    Fast search in overlapping intervals 
    (begin), (end, [associated offsets])
    """
    # Attribute type hinting
    limits: tuple[int, ...]
    results: list[list[int]]

    def __init__(self, intervals:list[tuple[int, int, tuple[int, ...]]]) -> None:
        limit2changes:dict[int, tuple[list[tuple[int, ...]], list[tuple[int, ...]]]] = dict()
        for index, (left, right, value) in enumerate(intervals):
            assert left < right
            if left not in limit2changes.keys():
                limit2changes[left] = ([],[])
            if right not in limit2changes.keys():
                limit2changes[right] = ([],[])

            limit2changes[left][0].append(value)
            limit2changes[right][1].append(value)
        limits, changes = zip(*sorted(limit2changes.items()))

        limits: tuple[int, ...]
        changes: tuple[tuple[list[tuple[int, ...]], ...], ...]

        self.limits = limits
        self.results = [[]]
        
        uniques:set[tuple[int, ...]] = set()
        offsets:dict[tuple[int, ...], int] = {}
        tmp_results:list[int] = []
        for index, (arrivals, departures) in enumerate(changes):
            
            uniques.difference_update(departures)
            for departure in departures:
                offsets.pop(departure)
            
            for unique in uniques:
                if not unique in offsets.keys():
                    offsets[unique] = 0
                offsets[unique] += (self.limits[index] - self.limits[index - 1]) 
            
            uniques.update(arrivals)
            for arrival in arrivals:
                offsets[arrival] = 0
            
            tmp_results.clear()
            for k,value in offsets.items():
                tmp_results.extend([i + value for i in k])
            self.results.append(tmp_results.copy())
        
    def __getitem__(self, element:int) -> list[int]:
        index = bisect(self.limits, element)
        difference = element - self.limits[index - 1]
        return [difference + value for value in self.results[index]]

    def get_values(self) -> zip:
        return zip(self.limits, self.results)