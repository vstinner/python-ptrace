#!/bin/bash
set -e
set -x
2to3 -w .
2to3 -w -d .
patch -p1 < python3.0.patch
