#! /bin/python

import argparse
import mmap
import sys

_python3 = sys.version_info.major == 3

def to_hex2(s):
    if _python3:
        r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        r = "".join("{0:02x}".format(ord(c)) for c in s)
    while r[0] == '0' and len(r) > 1: r = r[1:]
    return r

class DexHeader:
    def __init__(self, fmap):
        self.magic = fmap.read(3).decode('utf8')
        fmap.read_byte()
        self.version = fmap.read(3).decode('utf8')
        fmap.read_byte()
        self.checksum = fmap.read(4)[::-1]
        self.signature = fmap.read(20)[::-1]
        self.fileSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.headerSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.endianTag = fmap.read(4)[::-1]
        self.linkSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.linkOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.mapOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.stringIdsSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.stringIdsOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.typeIdsSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.typeIdsOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.protoIdsSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.protoIdsOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.fieldIdsSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.fieldIdsOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.methodIdsSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.methodIdsOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.classDefsSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.classDefsOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.dataSize = int.from_bytes(fmap.read(4), byteorder='little', signed=False)
        self.dataOff = int.from_bytes(fmap.read(4), byteorder='little', signed=False)

    def __str__(self):
        return '\n'.join(["magic %s %s" % (self.magic, self.version),
               "checksum 0x%s" % (to_hex2(self.checksum)),
               "file size %d" % (self.fileSize),
               "header size %d" % (self.headerSize),
               "endian tag 0x%s" % (to_hex2(self.endianTag)),
               "map offset %d(0x%08x)" % (self.mapOff, self.mapOff),
               "link size %d, offset %d(0x%08x)" % (self.linkSize, self.linkOff, self.linkOff),
               "string ids size %d, offset %d(0x%08x)" % (self.stringIdsSize, self.stringIdsOff, self.stringIdsOff),
               "type ids size %d, offset %d(0x%08x)" % (self.typeIdsSize, self.typeIdsOff, self.typeIdsOff),
               "proto ids size %d, offset %d(0x%08x)" % (self.protoIdsSize, self.protoIdsOff, self.protoIdsOff),
               "field ids size %d, offset %d(0x%08x)" % (self.fieldIdsSize, self.fieldIdsOff, self.fieldIdsOff),
               "method ids size %d, offset %d(0x%08x)" % (self.methodIdsSize, self.methodIdsOff, self.methodIdsOff),
               "class defs size %d, offset %d(0x%08x)" % (self.classDefsSize, self.classDefsOff, self.classDefsOff),
               "data size %d, offset %d(0x%08x)" % (self.dataSize, self.dataOff, self.dataOff)])

class StringId:
    def __init__(self):
        
if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=True, help="dex file path")
    args = vars(ap.parse_args())
    with open(args['file'], 'rb') as f:
        fmap = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
        dexHeader = DexHeader(fmap)
        print(dexHeader)

