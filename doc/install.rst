+++++++++++++++++++++
Install python-ptrace
+++++++++++++++++++++

python-ptrace supports Python 3.6 and newer.

Linux packages
==============

* Debian: `python-ptrace Debian package <http://packages.qa.debian.org/p/python-ptrace.html>`_.
* Mandriva: `python-ptrace Mandriva package <http://sophie.zarb.org/rpmfind?search=python-ptrace&st=rpmname>`_
* OpenEmbedded: `python-ptrace recipe <http://git.openembedded.net/?p=org.openembedded.dev.git;a=tree;f=packages/python>`_
* Arch Linux: `python-ptrace Arch Linux package <http://aur.archlinux.org/packages.php?ID=19609>`_
* Gentoo: `dev-python/python-ptrace <http://packages.gentoo.org/package/dev-python/python-ptrace>`_

See also `python-ptrace on Python Package Index (PyPI) <https://pypi.python.org/pypi/python-ptrace>`_

Install from source
===================

Download tarball
----------------

Get the latest tarball at the `Python Package Index (PyPI)
<https://pypi.python.org/pypi/python-ptrace>`_.

Download development version
----------------------------

Download the development version using Git::

    git clone https://github.com/vstinner/python-ptrace.git

`Browse python-ptrace source code
<https://github.com/vstinner/python-ptrace>`_.


Option dependency
-----------------

* distorm disassembler (optional)
  http://www.ragestorm.net/distorm/

Installation
------------

Note: pip is strongly recommanded.

Type as root::

   python3 setup.py install

Or using sudo program::

   sudo python3 setup.py install


cptrace
=======

For faster debug and to avoid ctypes, you can also install cptrace: Python
binding of the ptrace() function written in C::

    python3 setup_cptrace.py install


Run tests
=========

Run tests with tox
------------------

To run all tests, just type::

    tox

The `tox project <https://testrun.org/tox/latest/>`_ creates a clean virtual
environment to run tests.


Run tests manually
------------------

Type::

    python3 runtests.py
    python3 test_doc.py

It's also possible to run a specific test::

    PYTHONPATH=$PWD python3 tests/test_strace.py
