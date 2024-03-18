#!/usr/bin/env bash

trace() {
  (
    set +e
    python ../../strace.py -e execve $1; ec=$?
    if [ $ec -gt 0 ]; then
      exit $(($ec - 128 - $2))
    fi
  )
}

if command -v gcc && command -v make && command -v kill; then
  make || exit

  # trace ./invalid_read  $(kill -l SEGV) |& tee /dev/stderr | grep -q 'Invalid read from'
  trace ./invalid_read    $(kill -l SEGV)  # 2>&1 | grep -q 'Invalid read from'
  trace ./invalid_write   $(kill -l SEGV)  # 2>&1 | grep -q 'Invalid write to'
  trace ./stack_overflow  $(kill -l SEGV)  # 2>&1 | grep -q 'STACK OVERFLOW!'
  trace ./call_null       $(kill -l SEGV)
  trace ./abort           $(kill -l ABRT)
  trace ./div_zero        $(kill -l FPE)
  trace ./socket_ipv4_tcp
  trace ./pthread
  trace ./execve
  trace ./fork
fi
