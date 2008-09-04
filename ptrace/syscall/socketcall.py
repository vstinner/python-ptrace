from ptrace.cpu_info import CPU_WORD_SIZE
from ptrace.ctypes_tools import ntoh_ushort, ntoh_uint
from ptrace.syscall.socketcall_constants import SOCKETCALL, SOCKET_FAMILY
from ptrace.syscall.socketcall_struct import sockaddr, sockaddr_in, sockaddr_un
from ctypes import c_int
from ptrace.os_tools import RUNNING_LINUX
from socket import AF_INET, inet_ntoa
from struct import pack
if RUNNING_LINUX:
    from socket import AF_NETLINK
    from ptrace.syscall.socketcall_struct import sockaddr_nl

def ip_int2str(ip):
    """
    Convert an IP address (as an interger) to a string.

    >>> ip_int2str(0x7f000001)
    '127.0.0.1'
    """
    ip_bytes = pack("!I", ip)
    return inet_ntoa(ip_bytes)

AF_FILE = 1

def formatOptVal(argument):
    function = argument.function
    optlen = function["optlen"].value
    if optlen == 4:
        addr = argument.value
        text = function.process.readStruct(addr, c_int)
        return argument.formatPointer("<%s>" % text, addr)
    else:
        return None

def formatSockaddr(argument, argtype):
    address = argument.value
    value = argument.function.process.readStruct(address, sockaddr)
    family = value.family
    if family == AF_INET:
        return argument.readStruct(address, sockaddr_in)
    if family == AF_FILE:
        return argument.readStruct(address, sockaddr_un)
    if RUNNING_LINUX:
        if family == AF_NETLINK:
            return argument.readStruct(address, sockaddr_nl)
    family = SOCKET_FAMILY.get(family, family)
    return argument.formatPointer("<sockaddr family=%s>" % family, address)

def setupSocketCall(function, process, socketcall, address):
    # Reset function call
    function.clearArguments()
#    function.argument_class = SocketCallArgument

    # Setup new function call
    function.process = process
    function.name = socketcall.getText()

    # Create arguments
    formats = SOCKETCALL[socketcall.value][1]
    for argtype, argname in formats:
        value = process.readWord(address)
        function.addArgument(value, argname, argtype)
        address += CPU_WORD_SIZE

def formatSockaddrInStruct(argument, name, value):
    if name == "sin_port":
        return ntoh_ushort(value)
    if name == "sin_addr":
        ip = ntoh_uint(value.s_addr)
        return ip_int2str(ip)
    return None

