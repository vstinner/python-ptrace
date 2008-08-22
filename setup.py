#!/usr/bin/env python

MODULES = ["ptrace", "ptrace.binding", "ptrace.syscall", "ptrace.debugger"]

SCRIPTS = ("strace.py", "gdb.py")

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
]

LONG_DESCRIPTION = open('README').read() + open('ChangeLog').read()

def main():
    from imp import load_source
    from os import path
    from sys import argv

    if "--setuptools" in argv:
        argv.remove("--setuptools")
        from setuptools import setup
    else:
        from distutils.core import setup

    ptrace = load_source("version", path.join("ptrace", "version.py"))
    PACKAGES = {}
    for name in MODULES:
        PACKAGES[name] = name.replace(".", "/")

    install_options = {
        "name": ptrace.PACKAGE,
        "version": ptrace.VERSION,
        "url": ptrace.WEBSITE,
        "download_url": ptrace.WEBSITE,
        "author": "Victor Stinner",
        "description": "python binding of ptrace",
        "long_description": LONG_DESCRIPTION,
        "classifiers": CLASSIFIERS,
        "license": ptrace.LICENSE,
        "packages": PACKAGES.keys(),
        "package_dir": PACKAGES,
        "scripts": SCRIPTS,
    }
    setup(**install_options)

if __name__ == "__main__":
    main()

