from ctypes import Structure, c_char, c_ushort
from ptrace.ctypes_stdint import uint16_t, uint32_t

SOCKETCALL = {
    1: ("socket", (
        ("int", "family"),
        ("int", "type"),
        ("int", "protocol"),
    )),
    2: ("bind", (
        ("int", "fd"),
        ("struct sockaddr*", "umyaddr"),
        ("int", "addrlen"),
    )),
    3: ("connect", (
        ("int", "fd"),
        ("struct sockaddr*", "uservaddr"),
        ("int", "addrlen"),
    )),
    4: ("listen", (
        ("int", "fd"),
        ("int", "backlog"),
    )),
    5: ("accept", (
        ("int", "fd"),
        ("struct sockaddr*", "upeer_sockaddr"),
        ("int", "upeer_addrlen"),
    )),
    6: ("getsockname", (
        ("int", "fd"),
        ("struct sockaddr*", "sockaddr"),
        ("int", "sockaddr_len"),
    )),
    7: ("getpeername", (
        ("int", "fd"),
        ("struct sockaddr*", "sockaddr"),
        ("int", "sockaddr_len"),
    )),
    8: ("socketpair", (
        ("int", "family"),
        ("int", "type"),
        ("int", "protocol"),
        ("int*", "sockvec"),
    )),
    9: ("send", (
        ("int", "fd"),
        ("char*", "buf"),
        ("size_t", "len"),
        ("int", "flags"),
    )),
    10: ("recv", (
        ("int", "fd"),
        ("char*", "buf"),
        ("size_t", "len"),
        ("int", "flags"),
    )),
    11: ("sendto", (
        ("int", "fd"),
        ("char*", "buf"),
        ("size_t", "len"),
        ("int", "flags"),
        ("struct sockaddr*", "addr"),
        ("socklen_t", "addr_len"),
    )),
    12: ("recvfrom", (
        ("int", "fd"),
        ("char*", "buf"),
        ("size_t", "len"),
        ("int", "flags"),
        ("struct sockaddr*", "addr"),
        ("int*", "addr_len"),
    )),
    13: ("shutdown", (
        ("int", "fd"),
        ("int", "how"),
    )),
    14: ("setsockopt", (
        ("int", "fd"),
        ("int", "level"),
        ("int", "optname"),
        ("char*", "optval"),
        ("int", "optlen"),
    )),
    15: ("getsockopt", (
        ("struct socket*", "sock"),
        ("int", "level"),
        ("int", "optname"),
        ("char*", "optval"),
        ("int", "optlen"),
    )),
    16: ("sendmsg", (
        ("int", "fd"),
        ("struct msghdr*", "msg"),
        ("int", "flags"),
    )),
    17: ("recvmsg", (
        ("int", "fd"),
        ("struct msghdr*", "msg"),
        ("unsigned int", "flags"),
    )),
}

SOCKET_FAMILY = {
     0: "AF_UNSPEC",
     1: "AF_FILE",
     2: "AF_INET",
     3: "AF_AX25",
     4: "AF_IPX",
     5: "AF_APPLETALK",
     6: "AF_NETROM",
     7: "AF_BRIDGE",
     8: "AF_ATMPVC",
     9: "AF_X25",
    10: "AF_INET6",
    11: "AF_ROSE",
    12: "AF_DECnet",
    13: "AF_NETBEUI",
    14: "AF_SECURITY",
    15: "AF_KEY",
    16: "AF_NETLINK",
    17: "AF_PACKET",
    18: "AF_ASH",
    19: "AF_ECONET",
    20: "AF_ATMSVC",
    22: "AF_SNA",
    23: "AF_IRDA",
    24: "AF_PPPOX",
    25: "AF_WANPIPE",
    31: "AF_BLUETOOTH",
}

SOCKET_TYPE = {
     1: "SOCK_STREAM",
     2: "SOCK_DGRAM",
     3: "SOCK_RAW",
     4: "SOCK_RDM",
     5: "SOCK_SEQPACKET",
    10: "SOCK_PACKET",
}

SOCKET_PROTOCOL = {
     1: "IPPROTO_ICMP",
    58: "IPPROTO_ICMPV6",
}

SETSOCKOPT_LEVEL = {
    0: "SOL_IP",
    1: "SOL_SOCKET",
}

SETSOCKOPT_OPTNAME = {
   # level 0 (SOL_IP)
     1: "IP_TOS",
   # level 1 (SOL_SOCKET)
     2: "SO_REUSEADDR",
     9: "SO_KEEPALIVE",
    20: "SO_RCVTIMEO",
    21: "SO_SNDTIMEO",
}

sa_family_t = c_ushort

class sockaddr(Structure):
    _fields_ = (
        ("family", sa_family_t),
    )

class in_addr(Structure):
    _fields_ = (
        ("s_addr", uint32_t),
    )

# INET socket
class sockaddr_in(Structure):
    _fields_ = (
        ("sin_family", sa_family_t),
        ("sin_port", uint16_t),
        ("sin_addr", in_addr),
    )

# UNIX socket
class sockaddr_un(Structure):
    _fields_ = (
        ("sun_family", sa_family_t),
        ("sun_path", c_char*108),
    )

# Netlink socket
class sockaddr_nl(Structure):
    _fields_ = (
        ("nl_family", sa_family_t),
        ("nl_pad", c_ushort),
        ("nl_pid", uint32_t),
        ("nl_groups", uint32_t),
    )

