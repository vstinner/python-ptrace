#!/usr/bin/env python

import importlib.util

SOURCES = ['cptrace/cptrace.c']

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: C',
    'Programming Language :: Python',
]

LONG_DESCRIPTION = open('doc/cptrace.rst').read()


def main():
    from os import path
    from sys import argv

    if "--setuptools" in argv:
        argv.remove("--setuptools")
        from setuptools import setup, Extension
    else:
        from distutils.core import setup, Extension

    cptrace_ext = Extension('cptrace', sources=SOURCES)

    cptrace_spec = importlib.util.spec_from_file_location("version",
                                                          path.join("cptrace", "version.py"))
    cptrace = importlib.util.module_from_spec(cptrace_spec)
    cptrace_spec.loader.exec_module(cptrace)

    install_options = {
        "name": cptrace.PACKAGE,
        "version": cptrace.VERSION,
        "url": cptrace.WEBSITE,
        "download_url": cptrace.WEBSITE,
        "license": cptrace.LICENSE,
        "author": "Victor Stinner",
        "description": "python binding of ptrace written in C",
        "long_description": LONG_DESCRIPTION,
        "classifiers": CLASSIFIERS,
        "ext_modules": [cptrace_ext],
    }
    setup(**install_options)


if __name__ == "__main__":
    main()
