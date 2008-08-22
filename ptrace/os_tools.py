from sys import platform, version

RUNNING_PYPY = ("pypy" in version.lower())
RUNNING_WINDOWS = (platform == 'win32')
RUNNING_LINUX = (platform == 'linux2')
RUNNING_FREEBSD = platform.startswith('freebsd')
RUNNING_OPENBSD = platform.startswith('openbsd')
RUNNING_MACOSX = (platform == 'darwin')
RUNNING_BSD = RUNNING_FREEBSD or RUNNING_MACOSX or RUNNING_OPENBSD

HAS_PROC = RUNNING_LINUX
HAS_PTRACE = (RUNNING_BSD or RUNNING_LINUX)

