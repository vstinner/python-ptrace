from ctypes import cdll
from ctypes.util import find_library

LIBC_FILENAME = find_library('c')
libc = cdll.LoadLibrary(LIBC_FILENAME)

