#!/usr/bin/env python
import os
import re
import subprocess
import sys
import unittest

GDB = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'gdb.py'))


class TestGdb(unittest.TestCase):

    def run_command(self, command):
        if isinstance(command, str):
            command = command.encode('ascii')
        command = command + b'\n'
        args = [sys.executable, GDB, '--', sys.executable, '-c', 'pass']
        proc = subprocess.Popen(args,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        stdout, _ = proc.communicate(command)
        exitcode = proc.wait()
        self.assertEqual(exitcode, 0)
        if stdout.startswith(b'(gdb) '):
            stdout = stdout[6:]
        pos = stdout.rfind(b'(gdb) ')
        if pos:
            stdout = stdout[:pos]
        stdout = stdout.rstrip()
        if b'Traceback' in stdout:
            self.fail('Traceback in output: %r' % stdout)
        return stdout

    def check_stdout(self, pattern, stdout):
        self.assertTrue(re.search(pattern, stdout, re.MULTILINE),
                        (pattern, stdout))

    def test_proc(self):
        stdout = self.run_command('proc')
        for pattern in (
            b'^Process ID: [0-9]+',
            b'^Process state: ',
            b'^Process environment: ',
            b'^User identifier: [0-9]+',
            b'^Group identifier: [0-9]+',
        ):
            self.assertTrue(re.search(pattern, stdout, re.MULTILINE),
                            (pattern, stdout))

    def test_print(self):
        stdout = self.run_command('print 1+2')
        self.check_stdout(b'^Decimal: 3\n', stdout)

    def test_where(self):
        stdout = self.run_command('where')
        self.check_stdout(b'^CODE:', stdout)

    def test_regs(self):
        # Just check that the command doesn't raise an exception
        self.run_command('regs')

    def test_backtrace(self):
        # Just check that the command doesn't raise an exception
        self.run_command('backtrace')

    def test_maps(self):
        stdout = self.run_command('maps')
        self.check_stdout(b'^MAPS: ', stdout)

    def test_dbginfo(self):
        stdout = self.run_command('dbginfo')
        self.check_stdout(b'^Debugger process ID: [0-9]+', stdout)
        self.check_stdout(b'^python-ptrace version [0-9]+\\.[0-9]+', stdout)
        self.check_stdout(b'^Website: ', stdout)


if __name__ == "__main__":
    unittest.main()
