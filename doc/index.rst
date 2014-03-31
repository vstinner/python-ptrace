=============
python-ptrace
=============

python-ptrace is a debugger using ptrace (Linux, BSD and Darwin system call to
trace processes) written in Python.

* `python-ptrace documentation
  <http://python-pytrace.readthedocs.org/>`_
* `python-ptrace at Bitbucket
  <http://bitbucket.org/haypo/python-ptrace/>`_
* `python-ptrace at the Python Cheeseshop (PyPI)
  <http://pypi.python.org/pypi/python-ptrace>`_

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
   syscall
   gdb
   process
   todo
   changelog
   authors


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


Links
=====

Project using python-ptrace
---------------------------

* `Fusil the fuzzer <http://fusil.readthedocs.org>`_


python-ptrace announces
-----------------------

* `fuzzing mailing list <http://www.whitestar.linuxbox.org/pipermail/fuzzing/2008-February/000474.html>`_
* `reverse-engineering.net <http://www.reverse-engineering.net/viewtopic.php?f=10&t=6656>`_

ptrace usage
------------

* Sandboxing: `Plash <http://plash.beasts.org/>`_

Similar projects
----------------

* `vtrace <http://kenshoto.com/vtrace/>`_: Python library (Windows and Linux) supporting threads
* `subterfuge <http://subterfugue.org/>`_ by Mike Coleman: Python library (Linux): contains Python binding of ptrace written in C for Python 2.1/2.2. It doesn't work with Python 2.5 (old project, not maintained since 2002)
* `strace <http://sourceforge.net/projects/strace/>`_ program (Linux, BSD)
* ltrace program (Linux)
* truss program (Solaris and BSD)
* `pytstop <http://www.secdev.org/projects/pytstop/>`_ by Philippe Biondi: debugger similar to gdb but in very alpha stage (eg. no disassembler), using ptrace Python binding written in C (from subterfuge)
* `strace.py <http://www.secdev.org/articles/reverse/strace.py>`_ by Philippe Biondi
* `Fenris <http://lcamtuf.coredump.cx/fenris/>`_: suite of tools suitable for code analysis, debugging, protocol analysis, reverse engineering, forensics, diagnostics, security audits, vulnerability research
* `PyDBG <http://pedram.redhive.com/PaiMei/docs/>`_: Windows debugger written in pure Python

Interesting articles
-----------------------

* (fr) `Surveiller les connexions avec auditd <http://devloop.lyua.org/blog/index.php?2007/12/26/488-surveiller-les-connexions-avec-auditd>`_ (2007)
* `Playing with ptrace() for fun and proﬁt <http://actes.sstic.org/SSTIC06/Playing_with_ptrace/SSTIC06-Bareil-Playing_with_ptrace.pdf>`_ (2006)
* `PTRACE_SETOPTIONS tests <http://kerneltrap.org/node/5644>`_ (2005)
* `Process Tracing Using Ptrace <http://linuxgazette.net/issue81/sandeep.html>`_ (2002)

