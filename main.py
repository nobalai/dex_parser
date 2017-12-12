#! /usr/bin/python

import argparse
import mmap
from leb128 import uleb128_value, leb128_value
from struct import unpack, unpack_from

class DexHeader:
    def __init__(self, fmap):
        self.magic = fmap.read(3).decode('utf8')
        fmap.read_byte()
        self.version = fmap.read(3).decode('utf8')
        fmap.read_byte()
        self.checksum = unpack('<L', fmap.read(4))[0]
        self.signature = fmap.read(20)[::-1]
        self.fileSize = unpack('<L', fmap.read(4))[0]
        self.headerSize = unpack('<L', fmap.read(4))[0]
        self.endianTag = unpack('<L', fmap.read(4))[0]
        self.linkSize = unpack('<L', fmap.read(4))[0]
        self.linkOff = unpack('<L', fmap.read(4))[0]
        self.mapOff = unpack('<L', fmap.read(4))[0]
        self.stringIdsSize = unpack('<L', fmap.read(4))[0]
        self.stringIdsOff = unpack('<L', fmap.read(4))[0]
        self.typeIdsSize = unpack('<L', fmap.read(4))[0]
        self.typeIdsOff = unpack('<L', fmap.read(4))[0]
        self.protoIdsSize = unpack('<L', fmap.read(4))[0]
        self.protoIdsOff = unpack('<L', fmap.read(4))[0]
        self.fieldIdsSize = unpack('<L', fmap.read(4))[0]
        self.fieldIdsOff = unpack('<L', fmap.read(4))[0]
        self.methodIdsSize = unpack('<L', fmap.read(4))[0]
        self.methodIdsOff = unpack('<L', fmap.read(4))[0]
        self.classDefsSize = unpack('<L', fmap.read(4))[0]
        self.classDefsOff = unpack('<L', fmap.read(4))[0]
        self.dataSize = unpack('<L', fmap.read(4))[0]
        self.dataOff = unpack('<L', fmap.read(4))[0]

    def __str__(self):
        return '\n'.join(["magic %s %s" % (self.magic, self.version),
               "checksum %#.4x" % (self.checksum),
               "file size %d" % (self.fileSize),
               "header size %d" % (self.headerSize),
               "endian tag %#.4x" % (self.endianTag),
               "map offset %d(%#.4x)" % (self.mapOff, self.mapOff),
               "link size %d, offset %d(%#.4x)" % (self.linkSize, self.linkOff, self.linkOff),
               "string ids size %d, offset %d(%#.4x)" % (self.stringIdsSize, self.stringIdsOff, self.stringIdsOff),
               "type ids size %d, offset %d(%#.4x)" % (self.typeIdsSize, self.typeIdsOff, self.typeIdsOff),
               "proto ids size %d, offset %d(%#.4x)" % (self.protoIdsSize, self.protoIdsOff, self.protoIdsOff),
               "field ids size %d, offset %d(%#.4x)" % (self.fieldIdsSize, self.fieldIdsOff, self.fieldIdsOff),
               "method ids size %d, offset %d(%#.4x)" % (self.methodIdsSize, self.methodIdsOff, self.methodIdsOff),
               "class defs size %d, offset %d(%#.4x)" % (self.classDefsSize, self.classDefsOff, self.classDefsOff),
               "data size %d, offset %d(%#.4x)" % (self.dataSize, self.dataOff, self.dataOff)])

class StringIds:
    '''
    StringIds section
    The string data is encoded by uleb128
    '''
    def __init__(self, fmap, size, offset):
        self.offsets = unpack_from('<'+'L'*size, fmap, offset)
        self.data = list(map(lambda x: uleb128_value(fmap, x),
                             self.offsets))
        self.data = list(x for x,y in self.data)

    def __str__(self):
        h = "### StringIds section ###"
        g = ("#%d %d(%#.4x) %s" % (i, x[0], x[0], x[1])
             for i,x in enumerate(zip(self.offsets, self.data)))
        return h + '\n'.join(g)

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=True, help="dex file path")
    args = vars(ap.parse_args())
    with open(args['file'], 'rb') as f:
        fmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        dexHeader = DexHeader(fmap)
        print(dexHeader)

        stringIds = StringIds(fmap, dexHeader.stringIdsSize,
                              dexHeader.stringIdsOff)
        print(stringIds)
