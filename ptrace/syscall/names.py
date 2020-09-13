from ptrace.cpu_info import CPU_X86_64, CPU_I386, CPU_PPC64, CPU_PPC32, CPU_AARCH64
from ptrace.os_tools import RUNNING_LINUX, RUNNING_FREEBSD
if RUNNING_LINUX:
    if CPU_X86_64:
        from ptrace.syscall.linux.x86_64 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
    elif CPU_I386:
        from ptrace.syscall.linux.i386 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
    elif CPU_PPC64:
        from ptrace.syscall.linux.powerpc64 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
    elif CPU_PPC32:
        from ptrace.syscall.linux.powerpc32 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
    elif CPU_AARCH64:
        from ptrace.syscall.linux.aarch64 import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
    else:
        raise NotImplementedError("Unsupported CPU architecture")

elif RUNNING_FREEBSD:
    from ptrace.syscall.freebsd_syscall import SYSCALL_NAMES, SOCKET_SYSCALL_NAMES
else:
    SYSCALL_NAMES = {}
    SOCKET_SYSCALL_NAMES = set()
