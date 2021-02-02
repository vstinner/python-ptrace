#!/usr/bin/env python
import os
import re
import subprocess
import sys
import tempfile
import unittest
import signal

STRACE = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', 'strace.py'))

AARCH64 = (getattr(os.uname(), 'machine', None) == 'aarch64')


class TestStrace(unittest.TestCase):
    def strace(self, *args):
        """ Strace the given command and return the strace output. """
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
        self.assertIsNone(re.match(b'^Traceback', strace), strace)
        return strace, exitcode

    def assert_syscall(self, code, regex):
        """
        Strace the given python code and match the strace output against the
        given regular expression.
        """
        stdout, _ = self.strace(sys.executable, '-c', code)
        pattern = re.compile(regex, re.MULTILINE)
        self.assertTrue(pattern.search(stdout), stdout)

    def test_basic(self):
        stdout, _ = self.strace(sys.executable, '-c', 'pass')
        for syscall in (b'exit', b'mmap', b'open'):
            pattern = re.compile(b'^' + syscall, re.MULTILINE)
            self.assertTrue(pattern.search(stdout), stdout)

    def test_exitcode(self):
        for ec in range(2):
            stdout, exitcode = self.strace(sys.executable, '-c', 'exit(%d)' % ec)
            self.assertEqual(exitcode, ec)

    def test_exitsignal(self):
        signum = int(signal.SIGQUIT)
        stdout, exitcode = self.strace(sys.executable, '-c', 'import os; os.kill(os.getpid(), %d)' % signum)
        self.assertEqual(exitcode, (127 + 1) + signum)

    def test_getcwd(self):
        cwd = os.getcwd()
        stdout, _ = self.strace(sys.executable, '-c', 'import os; os.getcwd()')
        pattern = re.compile(b'^getcwd\\((.*),', re.MULTILINE)
        match = pattern.search(stdout)
        self.assertTrue(match, stdout)
        expected = repr(cwd)
        expected = os.fsencode(expected)
        self.assertEqual(match.group(1), expected)

    def test_open(self):
        code = 'open(%a).close()' % __file__
        self.assert_syscall(
            code, br"^open(at)?\(.*test_strace\.pyc?', O_RDONLY(\|O_CLOEXEC)?")

    def test_chdir(self):
        self.assert_syscall("import os; os.chdir('directory')",
                            br"^chdir\('directory'\)\s+= -2 ENOENT")

    def test_rename(self):
        pattern = br"^rename\('oldpath', 'newpath'\)"
        if AARCH64:
            pattern = br"^renameat\(.*'oldpath'.*'newpath'\)"
        self.assert_syscall("import os; os.rename('oldpath', 'newpath')",
                            pattern)

    def test_link(self):
        pattern = br"^link\('oldpath', 'newpath'\)"
        if AARCH64:
            pattern = br"^linkat\(.*'oldpath'.*'newpath'.*\)"
        self.assert_syscall("import os; os.link('oldpath', 'newpath')",
                            pattern)

    def test_symlink(self):
        pattern = br"^symlink\('target', 'linkpath'\)"
        if AARCH64:
            pattern = br"^symlinkat\(.*'target'.*'linkpath'\)"
        try:
            self.assert_syscall("import os; os.symlink('target', 'linkpath')",
                                pattern)
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
