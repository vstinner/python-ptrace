.. _syscall:

+++++++++++++++++++++++++++++
Trace system calls (syscalls)
+++++++++++++++++++++++++++++

python-ptrace can trace system calls using ``PTRACE_SYSCALL``.

PtraceSyscall
=============

ptrace.syscall module contains PtraceSyscall class: it's a parser of Linux
syscalls similar to strace program.

Example::

    connect(5, <sockaddr_in sin_family=AF_INET, sin_port=53, sin_addr=212.27.54.252>, 28) = 0
    open('/usr/lib/i686/cmov/libcrypto.so.0.9.8', 0, 0 <read only>) = 4
    mmap2(0xb7e87000, 81920, 3, 2066, 4, 297) = 0xb7e87000
    rt_sigaction(SIGWINCH, 0xbfb7d4a8, 0xbfb7d41c, 8) = 0

You can get more  informations: result type, value address, argument types, and
argument names.

Examples::

    long open(const char* filename='/usr/lib/i686/cmov/libcrypto.so.0.9.8' at 0xb7efc027, int flags=0, int mode=0 <read only>) = 4
    long fstat64(unsigned long fd=4, struct stat* buf=0xbfa46e2c) = 0
    long set_robust_list(struct robust_list_head* head=0xb7be5710, size_t len_ptr=12) = 0


strace.py
=========

Program strace.py is very close to strace program: display syscalls of a program. Example:


Features
--------

* Nice output of signal: see [[signal|python-ptrace signal handling]]
* Supports multiple processes
* Can trace running process
* Can display arguments name, type and address
* Option ``--filename`` to show only syscall using file names
* Option ``--socketcall`` to show only syscall related to network (socket usage)
* Option ``--syscalls`` to list all known syscalls


Example
-------

::

    $ ./strace.py /bin/ls
    execve(/bin/ls, [['/bin/ls'],|[/* 40 vars */]]) = 756
    brk(0)                                   = 0x0805c000
    access('/etc/ld.so.nohwcap', 0)          = -2 (No such file or directory)
    mmap2(NULL, 8192, 3, 34, -1, 0)          = 0xb7f56000
    access('/etc/ld.so.preload', 4)          = -2 (No such file or directory)
    (...)
    close(1)                                 = 0
    munmap(0xb7c5c000, 4096)                 = 0
    exit_group(0)
    ---done---


Options
-------

The program has many options. Example with ``--socketcall`` (display only
network functions)::

    $ ./strace.py --socketcall nc localhost 8080
    execve(/bin/nc, [['/bin/nc',|'localhost', '8080']], [[/*|40 vars */]]) = 12948
    socket(AF_FILE, SOCK_STREAM, 0)          = 3
    connect(3, <sockaddr_un sun_family=AF_FILE, sun_path=/var/run/nscd/socket>, 110) = -2 (No such file or directory)
    socket(AF_FILE, SOCK_STREAM, 0)          = 3
    connect(3, <sockaddr_un sun_family=AF_FILE, sun_path=/var/run/nscd/socket>, 110) = -2 (No such file or directory)
    socket(AF_INET, SOCK_STREAM, 6)          = 3
    setsockopt(3, SOL_SOCKET, SO_REUSEADDR, 3217455272L, 4) = 0
    connect(3, <sockaddr_in sin_family=AF_INET, sin_port=8080, sin_addr=127.0.0.1>, 16) = -111 (Connection refused)
    (...)

