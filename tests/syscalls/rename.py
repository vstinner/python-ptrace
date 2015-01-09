#!/usr/bin/env python
import os
import errno

try:
    os.rename('oldpath', 'newpath')
except OSError as e:
    if e.errno == errno.ENOENT:
        pass
    else:
        raise
