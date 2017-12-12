#! /usr/bin/python

import struct

def uleb128_value(m, off):
	size = 1
	result = m[off+0]
	if result > 0x7f :
		cur = m[off+1]
		result = (result & 0x7f) | ((cur & 0x7f) << 7)
		size += 1
		if cur > 0x7f :
			cur = m[off+2]
			result |= ((cur & 0x7f) << 14)
			size += 1
			if cur > 0x7f :
				cur = m[off+3]
				result |= ((cur & 0x7f) << 21)
				size += 1
				if cur > 0x7f :
					cur = m[off+4]
					result |= (cur << 28)
					size += 1
	return result, size

def leb128_value(content):
	value = 0

	mask=[0xffffff80,0xffffc000,0xffe00000,0xf0000000,0]
	bitmask=[0x40,0x40,0x40,0x40,0x8]
	value = 0
	for i in xrange(0,5):
		tmp = ord(content[i]) & 0x7f
		value = tmp << (i * 7) | value
		if (ord(content[i]) & 0x80) != 0x80:
			if bitmask[i] & tmp:
				value |= mask[i]
			break
	if i == 4 and (tmp & 0xf0) != 0:
		print("parse a error uleb128 number")
		return -1
	buffer = struct.pack("I",value)
	value, = struct.unpack("i",buffer)
	return i+1, value
