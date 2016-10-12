from ptrace.tools import readBits, formatBits
from ptrace.signames import signalName

# From /usr/include/bits/mman.h (Ubuntu Feisty, i386)
MMAP_PROT_BITMASK = (
    (1, "PROT_READ"),
    (2, "PROT_WRITE"),
    (4, "PROT_EXEC"),
    (0x01000000, "PROT_GROWSDOWN"),
    (0x02000000, "PROT_GROWSUP"),
)


def formatMmapProt(argument):
    return formatBits(argument.value, MMAP_PROT_BITMASK, "PROT_NONE")

# From /usr/include/bits/mman.h (Ubuntu Feisty, i386)
ACCESS_MODE_BITMASK = (
    (1, "X_OK"),
    (2, "W_OK"),
    (4, "R_OK"),
)


def formatAccessMode(argument):
    return formatBits(argument.value, ACCESS_MODE_BITMASK, "F_OK")

# From /usr/include/bits/fcntl.h (Ubuntu Feisty, i386)
OPEN_MODE_BITMASK = [
    (0o1, "O_WRONLY"),
    (0o2, "O_RDWR"),
    (0o100, "O_CREAT"),
    (0o200, "O_EXCL"),
    (0o400, "O_NOCTTY"),
    (0o1000, "O_TRUNC"),
    (0o2000, "O_APPEND"),
    (0o4000, "O_NONBLOCK"),
    (0o10000, "O_SYNC"),
    (0o20000, "O_ASYNC"),
    (0o40000, "O_DIRECT"),
    (0o100000, "O_LARGEFILE"),
    (0o200000, "O_DIRECTORY"),
    (0o400000, "O_NOFOLLOW"),
    (0o1000000, "O_NOATIME"),
    (0o2000000, "O_CLOEXEC"),
    (0o10000000, "O_PATH"),  # Linux 2.6.39
    (0o20200000, "O_TMPFILE"),  # Linux 3.11
]


def formatOpenMode(argument):
    value = argument.value
    flags = readBits(int(value), OPEN_MODE_BITMASK)

    # Add default access mode if neither of the others are present.
    if not flags or flags[0] not in ("O_WRONLY", "O_RDWR"):
        flags.insert(0, "O_RDONLY")

    text = "|".join(flags)
    if value:
        text = "%s (%s)" % (text, oct(argument.value))
    return text

CLONE_FLAGS_BITMASK = (
    (0x00000100, "CLONE_VM"),
    (0x00000200, "CLONE_FS"),
    (0x00000400, "CLONE_FILES"),
    (0x00000800, "CLONE_SIGHAND"),
    (0x00002000, "CLONE_PTRACE"),
    (0x00004000, "CLONE_VFORK"),
    (0x00008000, "CLONE_PARENT"),
    (0x00010000, "CLONE_THREAD"),
    (0x00020000, "CLONE_NEWNS"),
    (0x00040000, "CLONE_SYSVSEM"),
    (0x00080000, "CLONE_SETTLS"),
    (0x00100000, "CLONE_PARENT_SETTID"),
    (0x00200000, "CLONE_CHILD_CLEARTID"),
    (0x00400000, "CLONE_DETACHED"),
    (0x00800000, "CLONE_UNTRACED"),
    (0x01000000, "CLONE_CHILD_SETTID"),
    (0x02000000, "CLONE_STOPPED"),
    (0x04000000, "CLONE_NEWUTS"),
    (0x08000000, "CLONE_NEWIPC"),
)


def formatCloneFlags(argument):
    flags = argument.value
    bits = readBits(flags, CLONE_FLAGS_BITMASK)
    signum = flags & 0xFF
    if signum:
        bits.insert(0, signalName(signum))
    if bits:
        bits = "%s" % ("|".join(bits))
        return "<%s> (%s)" % (bits, str(flags))
    else:
        return str(flags)

AT_FDCWD = -100


def formatDirFd(value):
    return "AT_FDCWD" if value == AT_FDCWD else str(value)
