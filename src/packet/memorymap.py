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

# simple 'segment' namedtuple.
segment = collections.namedtuple("segment", ["start", "end", "mem"])

class memorymap(collections.abc.MutableSequence):
    """Maps a series of memoryview objects (or 'segments') into a single
logical address space."""

    __slots__ = {"_segtype", "segments", "_len"}


    def __init__(self, memviews, segtype=bytes):
        """Takes a list of memorymaps, memoryviews or objects supporting the
buffer interface, and creates a logical combination of their buffers.
The optional argument segtype defaults to 'bytes' and is used
for concatenating the values obtained using slices."""
        self._segtype = segtype
        self.segments = []
        offset = 0

        for memview in memviews:
            # If an object isn't a memorymap or memoryview,
            # try creating a memoryview object from it.
            if not isinstance(memview, memorymap) and\
                not isinstance(memview, memoryview):
                memview = memoryview(memview)

            orig_offset = offset
            offset += len(memview)
            self.segments.append(segment(orig_offset, offset, memview))

        self._len = self.segments[-1].end # Last segment's end


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
        """Returns the item(s) at the specified index or slice."""
        # If idx is a slice...
        if isinstance(idx, slice):
            # Return an instance of _segtype, with a list of all covered elements.
            return self._segtype(
                [self[i] for i in range(*idx.indices(len(self)))]
            )

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
