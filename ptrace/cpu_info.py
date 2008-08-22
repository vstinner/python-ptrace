from os import uname
from sys import byteorder
from ctypes import sizeof, c_void_p

CPU_BIGENDIAN = (byteorder == 'big')
CPU_64BITS = (sizeof(c_void_p) == 8)

if CPU_64BITS:
    CPU_WORD_SIZE = 8 # bytes
    CPU_MAX_UINT = 0xffffffffffffffff
else:
    CPU_WORD_SIZE = 4 # bytes
    CPU_MAX_UINT = 0xffffffff

# machine type from uname -m:
# "ppc" -> PowerPC 32 bits
# "i686" -> Intel 32 bits
# "x86_64" -> Intel 64 bits
_machine = uname()[4]
CPU_PPC32 = (_machine == 'ppc')
CPU_PPC64 = (_machine == 'ppc64')
CPU_I386 = (_machine in ("i386", "i686"))    # compatible Intel 32 bits
CPU_X86_64 = (_machine == "x86_64")  # compatible Intel 64 bits
del _machine

CPU_INTEL = (CPU_I386 or CPU_X86_64)
CPU_POWERPC = (CPU_PPC32 or CPU_PPC64)

