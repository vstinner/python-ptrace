=============
python-ptrace
=============

python-ptrace is a debugger using ptrace (Linux, BSD and Darwin system call to
trace processes) written in Python.

* `python-ptrace documentation
  <http://python-ptrace.readthedocs.io/>`_
* `python-ptrace at GitHub
  <https://github.com/haypo/python-ptrace>`_
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

Status:

* Supported operating systems: Linux, FreeBSD, OpenBSD
* Supported architectures: x86, x86_64 (Linux), PPC (Linux), ARM (Linux EAPI)

Missing features:

* Symbols: it's not possible to break on a function or read a variable value
* No C language support: debugger shows assembler code, not your C (C++ or other language) code!
* No thread support


Table of Contents
=================

.. toctree::
   :maxdepth: 2

   install
   usage
   syscall
   gdb
   process_events
   ptrace_signal
   cptrace
   authors
   changelog
   todo


Links
=====

Project using python-ptrace
---------------------------

* `Fusil the fuzzer <http://fusil.readthedocs.io>`_


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

