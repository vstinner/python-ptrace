#!/usr/bin/env python
import os
import re
import subprocess
import sys
import tempfile
import unittest
from ptrace import six

STRACE = os.path.normpath(os.path.join(
    os.path.dirname(__file__), '..', 'strace.py'))


class TestStrace(unittest.TestCase):

    def strace(self, *args):
        """ Strace the given command and return the strace output. """
        with tempfile.NamedTemporaryFile(mode='wb+') as temp:
            args = (sys.executable, STRACE, '-o', temp.name, '--') + args
            with open(os.devnull, "wb") as devnull:
                proc = subprocess.Popen(args,
                                        stdout=devnull,
                                        stderr=subprocess.STDOUT)
                proc.wait()

            temp.seek(0)
            strace = temp.readlines()
            strace = b''.join(strace)
        self.assertIsNone(re.match(b'^Traceback', strace), strace)
        return strace

    def assert_syscall(self, code, regex):
        """
        Strace the given python code and match the strace output against the
        given regular expression.
        """
        stdout = self.strace(sys.executable, '-c', code)
        pattern = re.compile(regex, re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

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
        self.assert_syscall(code,
                            br"^open\(.*test_strace\.pyc?', O_RDONLY(\|O_CLOEXEC)?")

    def test_chdir(self):
        self.assert_syscall(
            "import os; os.chdir('directory')",
            br"^chdir\('directory'\)\s+= -2 ENOENT")

    def test_rename(self):
        self.assert_syscall(
            "import os; os.rename('oldpath', 'newpath')",
            br"^rename\('oldpath', 'newpath'\)")

    def test_link(self):
        self.assert_syscall(
            "import os; os.link('oldpath', 'newpath')",
            br"^link\('oldpath', 'newpath'\)")

    def test_symlink(self):
        try:
            self.assert_syscall(
                "import os; os.symlink('target', 'linkpath')",
                br"^symlink\('target', 'linkpath'\)")
        finally:
            try:
                os.unlink('linkpath')
            except OSError:
                pass

    def test_socket(self):
        self.assert_syscall(
            "import socket; socket.socket(socket.AF_INET,socket.SOCK_STREAM).close()",
            br'^socket\(AF_INET, SOCK_STREAM(\|SOCK_CLOEXEC)?')


if __name__ == "__main__":
    unittest.main()
