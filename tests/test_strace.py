#!/usr/bin/env python
import os
import re
import subprocess
import sys
import unittest

PY3 = (sys.version_info >= (3,))
STRACE = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'strace.py'))

class TestStrace(unittest.TestCase):
    def strace(self, *args):
        args = (sys.executable, STRACE, '--') + args
        proc = subprocess.Popen(args,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        stdout, _ = proc.communicate()
        exitcode = proc.wait()
        self.assertEqual(exitcode, 0)
        self.assertFalse(b'Traceback' in stdout, stdout)
        return stdout

    def test_basic(self):
        stdout = self.strace(sys.executable, '-c', 'pass')
        for syscall in (b'exit', b'mmap', b'open'):
            pattern = re.compile(b'^' + syscall, re.MULTILINE)
            self.assertTrue(pattern.search(stdout), stdout)

    def test_getcwd(self):
        cwd = os.getcwd()
        if PY3:
            cwd = os.fsencode(cwd)
        stdout = self.strace(sys.executable, '-c', 'import os; os.getcwd()')
        pattern = re.compile(b'^getcwd\\((.*),', re.MULTILINE)
        match = pattern.search(stdout)
        self.assertTrue(match, stdout)
        expected = repr(cwd)
        if PY3:
            expected = os.fsencode(expected)
        self.assertEqual(match.group(1), expected)

    def test_socket(self):
        code = 'import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()'
        stdout = self.strace(sys.executable, '-c', code)
        pattern = re.compile(b'^socket\\(AF_INET, SOCK_STREAM, ', re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

if __name__ == "__main__":
    unittest.main()
