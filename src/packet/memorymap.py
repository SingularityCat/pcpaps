import collections.abc

"""memorymap: Providing a logically contiguous mapping of several memoryviews"""

# Maps multiple memoryviews into a single logical block.
#
# Ie:
# this -> that
#   _     _
# 0|A|  0|A|
# 1| |  1| |
# 2|_|  2|_|
#   _   3|B|
# 0|B|  4| |
# 1| |  5|_|
# 2|_|  6|C|
#   _   7| |
# 0|C|  8|_|
# 1| | 
# 2|_|
#

def clamp_start(idx, length):
    return max(0, min(length - 1, idx))

def clamp_end(idx, length):
    return None if idx < 0 else min(length, idx)

# simple 'segment' namedtuple.
segment = collections.namedtuple("segment", ["start", "end", "mem"])

class memorymap(collections.abc.MutableSequence):
    """Maps a series of memoryview objects (or 'segments') into a single
logical address space."""

    __slots__ = {"segments", "_len"}


    def __init__(self, obj, slc=slice(None,None,None)):
        # Initialise empty segment list.
        self.segments = []
        self._len = 0

        if isinstance(obj, memorymap):
            # Calculate index range.
            start, end, step = slc.indices(len(obj))

            # Find out if indices go forwards or backwards.
            backwards = start > end

            if backwards:
                # Copy segment list from parent.
                segs = obj.segments[::-1]
            else:
                # Copy segment list from parent in reverse.
                segs = obj.segments[:]

            # Iterate over segments.
            for seg in segs:
                # Test if there's any indices left in the slice.
                # If start > end and not backwards, then none left.
                # If start < end and backwards, then none left.
                # Else, some left.
                if (start < end) == backwards:
                    break

                seglen = seg.end - seg.start
                lstart = clamp_start(start - seg.start, seglen)
                lend = clamp_end(end - seg.start, seglen)

                if lend is None and not backwards:
                    continue

                sliced_seg = seg.mem[lstart:lend:step]

                # Add slice and increment start, if necessary.
                covered = len(sliced_seg) * step
                if covered != 0:
                    start += covered
                    self.add_segment(sliced_seg)

        elif isinstance(obj, collections.abc.Sequence):
            for seg in obj:
                self.add_segment(seg)

    def add_segment(self, memview):
        """Takes a memorymap, memoryview or object supporting the
buffer interface, and adds it to a logical combination of buffers."""
        # If an object isn't a memorymap or memoryview,
        # try creating a memoryview object from it.
        if not isinstance(memview, memorymap) and\
            not isinstance(memview, memoryview):
            memview = memoryview(memview)

        orig_len = self._len
        self._len += len(memview)
        self.segments.append(segment(orig_len, self._len, memview))


    def _map_idx(self, idx):
        """Return a tuple containing the segment index and the local index
for a given virtual index. Has a complexity of O(log n)"""
        # Support negative indices.
        idx = len(self) + idx if idx < 0 else idx

        # Initial range for the segment list.
        minidx = 0
        maxidx = len(self.segments)
        curidx = (maxidx - minidx) // 2

        segidx = None # The values to return
        locidx = None #

        # While there is a difference in range.
        while minidx < maxidx:
            # Current segment, in a more convinient form.
            seg = self.segments[curidx]

            # If index is in the current range, set return value and break.
            if seg.start <= idx < seg.end:
                segidx = curidx
                locidx = idx - seg.start
                break

            # Index is less than current range, take the left half.
            elif idx < seg.start:
                maxidx = curidx
                curidx = minidx + (maxidx - minidx) // 2

            # Index is greater than current range, take the right half.
            elif idx >= seg.end:
                minidx = curidx+1
                curidx = minidx + (maxidx - minidx) // 2

        return segidx, locidx


    def __len__(self):
        """Return the length of the logical memory map."""
        return self._len


    def __getitem__(self, idx):
        """Returns the item(s) at the specified index,
or returns a memorymap in the given range."""
        # If idx is a slice...
        if isinstance(idx, slice):
            return memorymap(self, slc=idx)
        else:
            # Get indexes.
            segidx, locidx = self._map_idx(idx)
            # Check if indices are valid, if not, raise and IndexError exception.
            if segidx is None or locidx is None:
                raise IndexError("Index out of range.")
            return self.segments[segidx].mem[locidx]


    def __setitem__(self, idx, val):
        """Sets the item(s) ad the specified index or slice."""
        # If idx is a slice...
        if isinstance(idx, slice):
            # For slice assignment, val should be iterable.
            if not isinstance(val, collections.Iterable):
                raise TypeError("Value is not iterable.")

            # Check the range of the slice,
            # if it differs from the range of the value, raise a TypeError.
            idxran = range(*idx.indices(len(self)))
            if len(idxran) != len(val):
                raise TypeError("Cannot alter size of mapping")

            # For each index in the range, and each value in the value...
            for i, com in zip(idxran, val):
                self[i] = com

        else:
            # Get indexes.
            segidx, locidx = self._map_idx(idx)
            # Check if indices are valid, if not, raise and IndexError exception.
            if segidx is None or locidx is None:
                raise IndexError("Index out of range.")
            self.segments[segidx].mem[locidx] = val


    def __delitem__(self, idx):
        """Deleting items is not allowed."""
        raise TypeError("Cannot delete item.")


    def insert(self, idx, val):
        """Inserting items is not allowed."""
        raise TypeError("Cannot create item.")


a = memoryview(bytearray(b"01234"))
b = memoryview(bytearray(b"56789"))
ab = memorymap([a, b])
ab_03 = ab[0:3]
print(bytes(ab_03))

