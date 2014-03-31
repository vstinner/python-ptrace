.. _signal:

+++++++++++++++++++++++++++++
python-ptrace signal handling
+++++++++++++++++++++++++++++

Introduction
============

PtraceSignal tries to display useful informations when a signal is received.
Depending on the signal number, it show different informations.

It uses the current instruction decoded as assembler code to understand why
the signal is raised.

Only Intel x86 (i386, maybe x86_64) is supported now.

When a process receives a signal, python-ptrace tries to explain why the signal was emited.

General informations (not shown for all signals, eg. not for SIGABRT):

* CPU instruction causing the crash
* CPU registers related to the crash
* Memory mappings of the memory addresses

Categorize signals:

* SIGFPE

  - Division by zero

* SIGSEGV, SIGBUS

  - Invalid memory read
  - Invalid memory write
  - Stack overflow
  - Invalid memory access

* SIGABRT

  - Program abort

* SIGCHLD

  - Child process exit

Examples
========

Division by zero (SIGFPE)
-------------------------

::

    Signal: SIGFPE
    Division by zero
    - instruction: IDIV DWORD [[EBP-0x8]
    - register ebp=0xbfdc4a98

Invalid memory read/write (SIGSEGV)
-----------------------------------

::

    Signal: SIGSEGV
    Invalid read from 0x00000008
    - instruction: MOV EAX, [EAX+0x8]]
    - mapping: 0x00000008 is not mapped in memory
    - register eax=0x00000000

::

    PID: 23766
    Signal: SIGSEGV
    Invalid write to 0x00000008 (size=4 bytes)
    - instruction: MOV DWORD [[EAX+0x8],|0x2a
    - mapping: 0x00000008..0x0000000b is not mapped in memory
    - register eax=0x00000000

Given informations:

* Address of the segmentation fault
* (if possible) Size of the invalid memory read/write
* CPU instruction causing the crash
* CPU registers related to the crash
* Memory mappings of the related memory address

Stack overflow (SIGSEGV)
------------------------

::

    Signal: SIGSEGV
    STACK OVERFLOW! Stack pointer is in 0xbf534000-0xbfd34000 => [stack]] (rw-p)
    - instruction: MOV BYTE [[EBP-0x1004],|0x0
    - mapping: 0xbf533430 is not mapped in memory
    - register <stack ptr>=0xbf533430
    - register ebp=0xbf534448

Child exit (SIGCHLD)
--------------------

::

    PID: 24008
    Signal: SIGCHLD
    Child process 24009 exited normally
    Signal sent by user 1000

Informations:

* Child process identifier
* Child process user identifier

Examples
========

Invalid read: ::

    Signal: SIGSEGV
    Invalid read from 0x00000008
    - instruction: MOV EAX, [EAX+0x8]
    - mapping: (no memory mapping)
    - register eax=0x00000000

Invalid write (MOV): ::

    Signal: SIGSEGV
    Invalid write to 0x00000008 (size=4 bytes)
    - instruction: MOV DWORD [EAX+0x8], 0x2a
    - mapping: (no memory mapping)
    - register eax=0x00000000

abort(): ::

    Signal: SIGABRT
    Program received signal SIGABRT, Aborted.

Source code
===========

See:

* ``ptrace/debugger/ptrace_signal.py``
* ``ptrace/debugger/signal_reason.py``


