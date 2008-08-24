#!/bin/bash
set -e
set -x
2to3 . > patch
patch -p0 < patch

2to3 -d . > patch
patch -p0 < patch
rm patch

patch -p1 < ptrace3000.patch
