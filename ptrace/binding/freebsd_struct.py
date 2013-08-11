from ctypes import (Structure,
    c_int, c_uint, c_ulong, c_void_p,
    c_uint16, c_uint32, c_size_t)
from ptrace.cpu_info import CPU_X86_64

PIOD_READ_D = 1
PIOD_WRITE_D = 2
PIOD_READ_I = 3
PIOD_WRITE_I = 4

# /usr/include/machine/reg.h
if CPU_X86_64:
    register_t = c_ulong
    class reg(Structure):
        _fields_ = (
	    ("r15", register_t),
	    ("r14", register_t),
	    ("r13", register_t),
	    ("r12", register_t),
	    ("r11", register_t),
	    ("r10", register_t),
	    ("r9", register_t),
	    ("r8", register_t),
	    ("rdi", register_t),
	    ("rsi", register_t),
	    ("rbp", register_t),
	    ("rbx", register_t),
	    ("rdx", register_t),
	    ("rcx", register_t),
	    ("rax", register_t),
	    ("trapno", c_uint32),
	    ("fs", c_uint16),
	    ("gs", c_uint16),
	    ("err", c_uint32),
	    ("es", c_uint16),
	    ("ds", c_uint16),
	    ("rip", register_t),
	    ("cs", register_t),
	    ("rflags", register_t),
	    ("rsp", register_t),
	    ("ss", register_t),
        )
else:
    class reg(Structure):
        _fields_ = (
            ("fs", c_uint),
            ("es", c_uint),
            ("ds", c_uint),
            ("edi", c_uint),
            ("esi", c_uint),
            ("ebp", c_uint),
            ("isp", c_uint),
            ("ebx", c_uint),
            ("edx", c_uint),
            ("ecx", c_uint),
            ("eax", c_uint),
            ("trapno", c_uint),
            ("err", c_uint),
            ("eip", c_uint),
            ("cs", c_uint),
            ("eflags", c_uint),
            ("esp", c_uint),
            ("ss", c_uint),
            ("gs", c_uint),
        )

class ptrace_io_desc(Structure):
    _fields_ = (
        ("piod_op", c_int),
        ("piod_offs", c_void_p),
        ("piod_addr", c_void_p),
        ("piod_len", c_size_t),
    )

