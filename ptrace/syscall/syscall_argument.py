from ptrace.cpu_info import CPU_WORD_SIZE
from ptrace.ctypes_tools import uint2int, formatWordHex, formatAddress
from ptrace.signames import signalName
from ctypes import c_int
from ptrace.error import PTRACE_ERRORS, writeError
from logging import getLogger, INFO
from ptrace.func_arg import FunctionArgument
from ptrace.syscall.posix_arg import (
    formatMmapProt, formatAccessMode, formatOpenFlags, formatCloneFlags, formatDirFd, formatOpenMode)
from ptrace.func_call import FunctionCall
from ptrace.syscall.socketcall import (setupSocketCall,
                                       formatOptVal, formatSockaddr, formatSockaddrInStruct, formatSockaddrIn6Struct)
from ptrace.syscall.socketcall_constants import SOCKETCALL
import os
import re

from ptrace.os_tools import RUNNING_LINUX, RUNNING_FREEBSD
from ptrace.syscall import FILENAME_ARGUMENTS
from ptrace.syscall.socketcall_constants import formatSocketType
if RUNNING_LINUX:
    from ptrace.syscall.linux_struct import (
        timeval, timespec, pollfd, rlimit, new_utsname, user_desc)
    from ptrace.syscall.linux_constants import SYSCALL_ARG_DICT, FD_SETSIZE
elif RUNNING_FREEBSD:
    from ptrace.syscall.freebsd_constants import SYSCALL_ARG_DICT
else:
    SYSCALL_ARG_DICT = {}


KNOWN_STRUCTS = []
if RUNNING_LINUX:
    KNOWN_STRUCTS.extend(
        (timeval, timespec, pollfd, rlimit, new_utsname, user_desc))
KNOWN_STRUCTS = dict((struct.__name__, struct) for struct in KNOWN_STRUCTS)

ARGUMENT_CALLBACK = {
    # Prototype: callback(argument) -> str
    "access": {"mode": formatAccessMode},
    "open": {"flags": formatOpenFlags, "mode": formatOpenMode},
    "openat": {"dirfd": formatDirFd, "flags": formatOpenFlags, "mode": formatOpenMode},
    "name_to_handle_at": {"dirfd": formatDirFd},
    "mmap": {"prot": formatMmapProt},
    "mmap2": {"prot": formatMmapProt},
    "clone": {"flags": formatCloneFlags},
    "socket": {"type": formatSocketType},
    "setsockopt": {"optval": formatOptVal},
}

POINTER_CALLBACK = {
    # Prototype: callback(argument, argtype) -> str
    "sockaddr": formatSockaddr,
}

STRUCT_CALLBACK = {
    # Prototype: callback(argument, attr_name, attr_value) -> str
    "sockaddr_in": formatSockaddrInStruct,
    "sockaddr_in6": formatSockaddrIn6Struct,
}

INTEGER_TYPES = set((
    "int", "size_t", "clockid_t", "long",
    "socklen_t", "pid_t", "uid_t", "gid_t",
))


def iterBits(data):
    for char in data:
        byte = ord(chr(char))
        for index in range(8):
            yield ((byte >> index) & 1) == 1


class SyscallArgument(FunctionArgument):

    def createText(self):
        value = self.value
        argtype = self.type
        name = self.name
        if not argtype or not name:
            return formatWordHex(self.value)

        syscall = self.function.name

        # Special cases
        try:
            return SYSCALL_ARG_DICT[syscall][name][value]
        except KeyError:
            pass
        try:
            callback = ARGUMENT_CALLBACK[syscall][name]
        except KeyError:
            callback = None
        if callback:
            return callback(self)
        if syscall == "execve":
            if name in ("argv", "envp"):
                return self.readCStringArray(value)
        if syscall == "socketcall":
            if name == "call":
                try:
                    return SOCKETCALL[value]
                except KeyError:
                    return str(value)
            if name == "args":
                func_call = FunctionCall("socketcall", self.options)
                setupSocketCall(func_call, self.function.process,
                                self.function[0], self.value)
                text = "<%s>" % func_call.format()
                return self.formatPointer(text, self.value)
        if syscall == "write" and name == "buf":
            fd = self.function[0].value
            if fd < 3:
                length = self.function[2].value
                return self.readString(value, length)
        if name == "signum":
            return signalName(value)

        # Remove "const " prefix
        if argtype.startswith("const "):
            argtype = argtype[6:]

        if name in FILENAME_ARGUMENTS and argtype == "char *":
            return self.readCString(value)

        # Format depending on the type
        if argtype.endswith("*"):
            try:
                # Strip in case there is a space between the name and '*'
                text = self.formatValuePointer(argtype[:-1].strip())
                if text:
                    return text
            except PTRACE_ERRORS as err:
                writeError(
                    getLogger(), err, "Warning: Format %r value error" % self, log_level=INFO)
            return formatAddress(self.value)

        # Array like "int[2]"
        match = re.match(r"(.*)\[([0-9])+\]", argtype)
        if match:
            basetype = match.group(1)
            count = int(match.group(2))
            if basetype == "int":
                return self.readArray(self.value, c_int, count)

        # Simple types
        if argtype in ("unsigned int", "unsigned long", "u32"):
            return str(self.value)
        if argtype in INTEGER_TYPES:
            return str(uint2int(self.value))

        # Default formatter: hexadecimal
        return formatWordHex(self.value)

    def formatValuePointer(self, argtype):
        address = self.value

        if not address:
            return "NULL"
        if argtype.startswith("struct "):
            argtype = argtype[7:]

        # Try a callback
        try:
            callback = POINTER_CALLBACK[argtype]
        except KeyError:
            callback = None
        if callback:
            return callback(self, argtype)

        if argtype == "int":
            pointee = self.function.process.readStruct(address, c_int)
            return self.formatPointer("<%s>" % pointee, address)
        if argtype in KNOWN_STRUCTS:
            struct = KNOWN_STRUCTS[argtype]
            return self.readStruct(address, struct)
        if RUNNING_LINUX and argtype == "fd_set":
            # The function is either select or pselect, so arg[0] is nfds
            nfds = self.function.arguments[0].value
            fd_set = filter(lambda x: int(x) < nfds, self.readBits(address, FD_SETSIZE))
            return self.formatPointer("[%s]" % " ".join(fd_set), address)

        syscall = self.function.name
        if syscall == "rt_sigprocmask" and argtype == "sigset_t":
            size = self.function["sigsetsize"].value * 8

            def formatter(key):
                key += 1
                return signalName(key)
            fd_set = self.readBits(address, size, format=formatter)
            return self.formatPointer("<sigset=(%s)>" % " ".join(fd_set), address)
        return None

    def readBits(self, address, count, format=str):
        bytes = self.function.process.readBytes(address, count // 8)
        fd_set = [format(index)
                  for index, bit in enumerate(iterBits(bytes)) if bit]
        return fd_set

    def readCString(self, address):
        if address:
            max_size = self.options.string_max_length
            data, truncated = self.function.process.readCString(
                address, max_size)
            text = os.fsdecode(data)
            text = repr(text)
            if truncated:
                text += "..."
        else:
            text = "NULL"
        return self.formatPointer(text, address)

    def readString(self, address, size):
        if address:
            max_len = self.options.string_max_length
            truncated = (max_len < size)
            size = min(size, max_len)
            data = self.function.process.readBytes(address, size)
            text = os.fsdecode(data)
            text = repr(text)
            if truncated:
                text += "..."
        else:
            text = "NULL"
        return self.formatPointer(text, address)

    def readCStringArray(self, address):
        if not address:
            return "NULL"
        address0 = address
        max_count = self.options.max_array_count
        text = []
        while True:
            str_addr = self.function.process.readWord(address)
            address += CPU_WORD_SIZE
            text.append(self.readCString(str_addr))
            if not str_addr:
                break
            if max_count <= len(text):
                text.append("(... more than %s strings ...)" % max_count)
                break
        text = "<(%s)>" % ", ".join(text)
        return self.formatPointer(text, address0)

    def formatStructValue(self, struct, name, value):
        if struct in STRUCT_CALLBACK:
            callback = STRUCT_CALLBACK[struct]
            return callback(self, name, value)
        return None
