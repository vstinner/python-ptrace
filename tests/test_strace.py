#!/usr/bin/env python
import os
import re
import subprocess
import sys
import tempfile
import unittest
from ptrace import six

STRACE = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'strace.py'))

class TestStrace(unittest.TestCase):
    def strace(self, *args):
        with tempfile.NamedTemporaryFile(mode='wb+') as temp:
            args = (sys.executable, STRACE, '-o', temp.name, '--') + args
            with open(os.devnull, "wb") as devnull:
                proc = subprocess.Popen(args,
                                        stdout=devnull,
                                        stderr=subprocess.STDOUT)
                exitcode = proc.wait()

            temp.seek(0)
            strace = temp.readlines()
            strace = b''.join(strace)
        self.assertEqual(exitcode, 0)
        self.assertIsNone(re.match(b'^Traceback', strace), strace)
        return strace

    def test_basic(self):
        stdout = self.strace(sys.executable, '-c', 'pass')
        for syscall in (b'exit', b'mmap', b'open'):
            pattern = re.compile(b'^' + syscall, re.MULTILINE)
            self.assertTrue(pattern.search(stdout), stdout)

    def test_getcwd(self):
        cwd = os.getcwd()
        stdout = self.strace(sys.executable, '-c', 'import os; os.getcwd()')
        pattern = re.compile(b'^getcwd\\((.*),', re.MULTILINE)
        match = pattern.search(stdout)
        self.assertTrue(match, stdout)
        expected = repr(cwd)
        if six.PY3:
            expected = os.fsencode(expected)
        self.assertEqual(match.group(1), expected)

    def test_open(self):
        if six.PY3:
            code = 'open(%a).close()' % __file__
        else:
            code = 'open(%r).close()' % __file__
        stdout = self.strace(sys.executable, '-c', code)
        pattern = re.compile(br"^open\(.*test_strace\.pyc?', <?O_RDONLY(\|O_CLOEXEC)?", re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

    def test_chdir(self):
        code = 'import os; os.chdir("directory")'
        stdout = self.strace(sys.executable, '-c', code)
        pattern = re.compile(br"^chdir\('directory'\)", re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

    def test_socket(self):
        code = 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()'
        stdout = self.strace(sys.executable, '-c', code)
        pattern = re.compile(br'^socket\(AF_INET, SOCK_STREAM(\|SOCK_CLOEXEC)?, ', re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

    def test_openat(self):
        code = 'import os; os.listdir(os.curdir)'
        stdout = self.strace(sys.executable, '-c', code)
        pattern = re.compile(br"^openat\(AT_FDCWD, '\.', <O_RDONLY\|O_NONBLOCK\|O_DIRECTORY(\|O_CLOEXEC)?>[^,]+, O_RDONLY\)", re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

if __name__ == "__main__":
    unittest.main()
