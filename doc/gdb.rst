++++++
gdb.py
++++++

``gdb.py`` is a command line debugger *similar to gdb*, but with fewer
features: no symbol support, no C language support, no thread support, etc.

Some commands
=============

* ``cont``: continue execution
* ``stepi``: execute one instruction
* ``step``: execute one instruction, but don't enter into calls

Type ``help`` to list all available commands.


Features
========

* print command displays value as decimal and hexadecimal, but also the related
  memory mapping (if any)::

    (gdb) print $eip
    Decimal: 3086383120
    Hexadecimal: 0xb7f67810
    Address is part of mapping: 0xb7f67000-0xb7f81000 => /lib/ld-2.6.1.so (r-xp)

* Nice output of signal: see [[signal|python-ptrace signal handling]]
* Syscall tracer with command "sys": see `python-ptrace system call tracer <syscall>`. Short example::

    (gdb) sys
    long access(char* filename='/etc/ld.so.nohwcap' at 0xb7f7f35b, int mode=F_OK) = -2 (No such file or directory)

* Supports multiple processes::

    (gdb) proclist
    <PtraceProcess #24187> (active)
    <PtraceProcess #24188>
    (gdb) proc
    Process ID: 24187 (parent: 24182)
    Process state: T (traced)
    Process command line: [['tests/fork_execve']
    (...)
    (gdb)|switch; proc
    Switch to <PtraceProcess #24188>
    Process ID: 24188 (parent: 24187)
    Process state: T (traced)
    Process command line: ['/bin/ls']]
    (...)

* Allow multiple commands on the same line using ";" separator::

    (gdb) print $eax; set $ax=0xdead; print $eax
    Decimal: 0
    Hexadecimal: 0x00000000
    Set $ax to 57005
    Decimal: 57005
    Hexadecimal: 0x0000dead

* Only written in pure Python code, so it's easy to extend
* Expression parser supports all arithmetic operator (``a+b``, ``a/b``, ``a<<b``, ``a&b``,
  ``...``), parenthesis, use of registers, etc. and pointer dereference
  (ex: ``print *($ebx+0xc)``).


Screnshot
=========

::

    $ ./gdb.py ls
    execve(/bin/ls, [['/bin/ls'],|[/* 40 vars */]]) = 16182
    (gdb) where
    ASM 0xb7f47810: MOV EAX, ESP <==
    ASM 0xb7f47812: CALL 0xb7f47a60
    ASM 0xb7f47817: MOV EDI, EAX
    ASM 0xb7f47819: CALL 0xb7f47800
    (gdb) regs
         EBX = 0xb7f4781e
         ECX = 0x0001d2f4
         EDX = 0xb7f61ff4
         ESI = 0x00000000
         (...)
    (gdb) proc
    Process ID: 16182
    Process command line: [['/bin/ls']
    Process|environment: ['TERM=xterm', 'SHELL=/bin/bash', (...)]]
    Process working directory: /home/haypo/prog/fusil/ptrace/trunk
    (gdb) stack
    STACK: 0xbfc58000..0xbfc6e000
    STACK -8: 0x00000000
    STACK -4: 0xb7f4781e
    STACK +0: 0x00000001
    STACK +4: 0xbfc6c6bb
    STACK +8: 0x00000000
    (gdb) maps
    MAPS: 08048000-0805b000 r-xp 00000000 08:03 2588939    /bin/ls
    MAPS: 0805b000-0805c000 rw-p 00012000 08:03 2588939    /bin/ls
    (...)
    MAPS: b7f61000-b7f63000 rw-p 00019000 08:03 1540553    /lib/ld-2.6.1.so
    MAPS: bfc58000-bfc6e000 rw-p bfc58000 00:00 0          [[stack]
    MAPS:|ffffe000-fffff000 r-xp 00000000 00:00 0          [vdso]]
    (gdb) quit
    Quit.
    Terminate <PtraceProcess pid=16182>
    Quit gdb.

