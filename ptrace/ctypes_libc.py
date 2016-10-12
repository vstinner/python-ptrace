"""
Load the system C library. Variables:
 - LIBC_FILENAME: the C library filename
 - libc: the loaded library
"""

from ctypes import CDLL
from ctypes.util import find_library

LIBC_FILENAME = find_library('c')
libc = CDLL(LIBC_FILENAME, use_errno=True)
