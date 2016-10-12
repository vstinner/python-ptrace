+++++++++++++++++++++
Install python-ptrace
+++++++++++++++++++++

Linux packages
==============

* Debian: `python-ptrace Debian package <http://packages.qa.debian.org/p/python-ptrace.html>`_.
* Mandriva: `python-ptrace Mandriva package <http://sophie.zarb.org/rpmfind?search=python-ptrace&st=rpmname>`_
* OpenEmbedded: `python-ptrace recipe <http://git.openembedded.net/?p=org.openembedded.dev.git;a=tree;f=packages/python>`_
* Arch Linux: `python-ptrace Arch Linux package <http://aur.archlinux.org/packages.php?ID=19609>`_
* Gentoo: `dev-python/python-ptrace <http://packages.gentoo.org/package/dev-python/python-ptrace>`_

See also `python-ptrace on Python Package Index (PyPI) <http://pypi.python.org/pypi/python-ptrace>`_

Install from source
===================

Download tarball
----------------

Get the latest tarball at the `Python Package Index (PyPI)
<http://pypi.python.org/pypi/python-ptrace>`_.

Download development version
----------------------------

Download the development version using Mercurial::

    git clone https://github.com/haypo/python-ptrace.git

`Browse python-ptrace source code
<https://github.com/haypo/python-ptrace>`_.


python-ptrace dependencies
--------------------------

* Python 2.6+/3.3+:
  http://python.org/
* distorm disassembler (optional)
  http://www.ragestorm.net/distorm/


Installation
------------

Type as root::

   python setup.py install

Or using sudo program::

   sudo python setup.py install


cptrace
=======

For faster debug and to avoid ctypes, you can also install cptrace: Python
binding of the ptrace() function written in C::

    python setup_cptrace.py install


Run tests
=========

Run tests with tox
------------------

The `tox project <https://testrun.org/tox/latest/>`_ can be used to build a
virtual environment run tests against different Python versions (Python 2 and
Python 3).

To run all tests on Python 2 and Python 3, just type::

    tox

To only run tests on Python 2.7, type::

    tox -e py2

Available environments:

* ``py2``: Python 2
* ``py3``: Python 3


Run tests manually
------------------

Type::

    python runtests.py
    python test_doc.py

It's also possible to run a specific test::

    PYTHONPATH=$PWD python tests/test_strace.py
