from struct import pack, unpack
from ptrace.cpu_info import CPU_64BITS
from ctypes import cast, POINTER

def int2uint64(value):
    if value < 0:
        return 0x10000000000000000 + value
    else:
        return value

def uint2int64(value):
    if value & 0x8000000000000000:
        return value - 0x10000000000000000
    else:
        return value

def truncateWord32(value):
    return value & 0xFFFFFFFF

def truncateWord64(value):
    return value & 0xFFFFFFFFFFFFFFFF

def formatUintHex16(value):
    return "0x%04x" % value

def formatUintHex32(value):
    return "0x%08x" % value

def formatUintHex64(value):
    return "0x%016x" % value

def int2uint32(value):
    if value < 0:
        return 0x100000000 + value
    else:
        return value

def uint2int32(value):
    if value & 0x80000000:
        return value - 0x100000000
    else:
        return value

uint2int = uint2int32
int2uint = int2uint32
if CPU_64BITS:
    ulong2long = uint2int64
    long2ulong = int2uint64
    formatWordHex = formatUintHex64
    truncateWord = truncateWord64
else:
    ulong2long = uint2int32
    long2ulong = int2uint32
    formatWordHex = formatUintHex32
    truncateWord = truncateWord32

def formatAddress(address):
    if address:
        return formatWordHex(address)
    else:
        return "NULL"

def formatAddressRange(start, end):
    return "%s-%s" % (formatWordHex(start), formatWordHex(end))

def ntoh_ushort(value):
    return unpack("<H", pack(">H", value))[0]

def ntoh_uint(value):
    return unpack("<I", pack(">I", value))[0]

def word2bytes(word):
    return pack("L", word)

def bytes2word(bytes):
    return unpack("L", bytes)[0]

def bytes2type(bytes, type):
    return cast(bytes, POINTER(type))[0]

def bytes2array(bytes, basetype, size):
    return bytes2type(bytes, basetype * size)

