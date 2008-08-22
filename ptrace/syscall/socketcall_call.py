from ptrace.func_arg import FunctionArgument
from ptrace.cpu_info import CPU_WORD_SIZE
from ptrace.ctypes_tools import ntoh_ushort, ntoh_uint
from ptrace.syscall.socketcall import (
    SOCKETCALL, SOCKET_FAMILY, SOCKET_TYPE, SOCKET_PROTOCOL,
    SETSOCKOPT_LEVEL, SETSOCKOPT_OPTNAME,
    sockaddr, sockaddr_in, sockaddr_un, sockaddr_nl)
from ctypes import c_int
from ptrace.os_tools import RUNNING_LINUX
from socket import AF_INET, inet_ntoa
from struct import pack
if RUNNING_LINUX:
    from socket import AF_NETLINK

def ip_int2str(ip):
    """
    Convert an IP address (as an interger) to a string.

    >>> ip_int2str(0x7f000001)
    '127.0.0.1'
    """
    ip_bytes = pack("!I", ip)
    return inet_ntoa(ip_bytes)

AF_FILE = 1

class SocketCallArgument(FunctionArgument):
    def createText(self):
        syscall = self.function.name
        name = self.name
        argtype = self.type
        value = self.value
        if syscall == "socket":
            if name == "family":
                return SOCKET_FAMILY.get(value, value)
            if name == "type":
                return SOCKET_TYPE.get(value, value)
            if name == "protocol":
                return SOCKET_PROTOCOL.get(value, value)
        if syscall == "setsockopt":
            if name == "level":
                return SETSOCKOPT_LEVEL.get(value, value)
            if name == "optname":
                return SETSOCKOPT_OPTNAME.get(value, value)
            if name == "optval":
                optlen = self.function["optlen"].value
                if optlen == 4:
                    text = self.function.process.readStruct(self.value, c_int)
                    return self.formatPointer("<%s>" % text, self.value)
        if argtype == "struct sockaddr*":
            address = self.value
            addr = self.function.process.readStruct(address, sockaddr)
            family = addr.family
            if family == AF_INET:
                return self.readStruct(self.value, sockaddr_in)
            elif family == AF_FILE:
                return self.readStruct(self.value, sockaddr_un)
            elif family == AF_NETLINK:
                return self.readStruct(self.value, sockaddr_nl)
            else:
                family = SOCKET_FAMILY.get(family, family)
                return self.formatPointer("<sockaddr family=%s>" % family, address)
        return None

    def formatStructValue(self, struct, name, value):
        if struct.startswith("sockaddr") and name.endswith("family"):
            return SOCKET_FAMILY.get(value, value)
        if struct == "sockaddr_in":
            if name == "sin_port":
                return ntoh_ushort(value)
            if name == "sin_addr":
                ip = ntoh_uint(value.s_addr)
                return ip_int2str(ip)
        return None


def setupSocketCall(function, process, socketcall, address):
    # Reset function call
    function.clearArguments()
    function.argument_class = SocketCallArgument

    # Setup new function call
    function.process = process
    function.name = socketcall.getText()

    # Create arguments
    formats = SOCKETCALL[socketcall.value][1]
    for argtype, argname in formats:
        value = process.readWord(address)
        function.addArgument(value, argname, argtype)
        address += CPU_WORD_SIZE

