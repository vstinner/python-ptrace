#!/usr/bin/env python
import os
import re
import subprocess
import sys
import unittest

STRACE = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'strace.py'))

class TestStrace(unittest.TestCase):
    def test_strace(self):
        args = [sys.executable, STRACE, '--', sys.executable, '-c', 'pass']
        proc = subprocess.Popen(args,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        stdout, _ = proc.communicate()
        exitcode = proc.wait()
        self.assertFalse(b'Traceback' in stdout, stdout)
        for syscall in ('exit', 'mmap', 'open'):
            pattern = re.compile(b'^' + syscall, re.MULTILINE)
            self.assertTrue(pattern.search(stdout), stdout)
        self.assertEqual(exitcode, 0)

if __name__ == "__main__":
    unittest.main()
