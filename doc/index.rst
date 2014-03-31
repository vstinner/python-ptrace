=============
python-ptrace
=============

python-ptrace is a debugger using ptrace (Linux, BSD and Darwin system call to
trace processes) written in Python.

* `python-ptrace documentation <http://bitbucket.org/haypo/python-ptrace/wiki/Home>`_
* `python-ptrace at Bitbucket <http://bitbucket.org/haypo/python-ptrace/wiki/Home>`_
* `python-ptrace at the Python Cheeseshop (PyPI) <http://pypi.python.org/pypi/python-ptrace>`_

python-ptrace is an opensource project written in Python under GNU GPLv2
license.

Features
========

* High level Python object API : PtraceDebugger and PtraceProcess
* Able to control multiple processes: catch fork events on Linux
* Read/write bytes to arbitrary address: take care of memory alignment and
  split bytes to cpu word
* Execution step by step using ptrace_singlestep() or hardware interruption 3
* Can use `distorm <http://www.ragestorm.net/distorm/>`_ disassembler
* Dump registers, memory mappings, stack, etc.
* :ref:`Syscall tracer and parser <syscall>` (strace.py command)

Status
======

The binding works on:

* Linux version 2.6.20 on i386, x86_64, PPC (may works on Linux 2.4.x
  and 2.6.x)
* Linux version 2.4 on PPC
* FreeBSD version 7.0RC1 on i386 (may works on FreeBSD 5.x/6.x)
* OpenBSD version 4.2 on i386
* Experimental support of ARM architecture (Linux EAPI),
  strace.py has been tested on Raspberry Pi (armv6l)

Some important features are missing:

* Symbols: it's not possible to break on a function or read a variable value
* No C language support: debugger shows assembler code, not your C (C++ or other language) code!
* No thread support

python-ptrace 0.6.3 was tested on:

* Linux version 2.6.32 on x86_64 with Python 2.6 and 3.1 and distorm3

python-ptrace 0.6.2 works on:

* Linux version 2.6.20 on i386, x86_64 and PPC32 (may works on Linux 2.4.x and 2.6.x)
* FreeBSD version 6.2 and 7.0 on i386 (may works on FreeBSD 5.x)

Table of Contents
=================

.. toctree::
   :maxdepth: 2

   install
   cptrace
   process_events
   ptrace_signal
   todo
   changelog
   authors

Pages:

* [[Documentation|Documentation]]
* [[syscall|Trace system call with python-ptrace]]
* [[gdb|python-ptrace gdb.py]]
* [[signal|python-ptrace signal handling]]
* [[Contact|Contact]]
* [[Links|Links]]


News
====

* 2013-12-16: Release of python-ptrace 0.6.6
* 2013-06-06: Release of python-ptrace 0.6.5
* 2012-02-26: Release of python-ptrace 0.6.4
* 2011-02-16: Release of python-ptrace 0.6.3
* 2009-11-09: Release of python-ptrace 0.6.2
* 2009-07-31: Project website moved to http://bitbucket.org/haypo/python-ptrace/
* 2009-02-13: Release of python-ptrace 0.6
* 2008-09-13: Release of python-ptrace 0.5

  - Parse socket syscalls for FreeBSD
  - Avoid creation of zombi process on FreeBSD
  - Most basic Windows support

Read also the :ref:`changelog <changelog>`.

Project using python-ptrace
===========================

* `Fusil the fuzzer <http://fusil.readthedocs.org>`_

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

