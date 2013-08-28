"""
Define standard (integers) types.

Signed types:
 - int8_t
 - int16_t
 - int32_t
 - int64_t
 - size_t

Unsigned types:
 - uint8_t
 - uint16_t
 - uint32_t
 - uint64_t
"""

import ctypes

# 8-bit integers
int8_t = ctypes.c_int8
uint8_t = ctypes.c_uint8

# 16-bit integers
int16_t = ctypes.c_int16
uint16_t = ctypes.c_uint16

# 32-bit integers
int32_t = ctypes.c_int32
uint32_t = ctypes.c_uint32

# 64-bit integers
int64_t = ctypes.c_int64
uint64_t = ctypes.c_uint64

# size_t
size_t = ctypes.c_size_t

__all__ = (
    "uint8_t", "int8_t", "int16_t", "uint16_t",
    "int32_t", "uint32_t", "int64_t", "uint64_t", "size_t")
