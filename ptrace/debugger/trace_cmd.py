from os import fork, execv, close, dup2
from subprocess import MAXFD
from ptrace.process_tools import DEV_NULL_FILENAME
from ptrace.binding import ptrace_traceme
from ptrace import PtraceError
from sys import stderr, exit

def traceCommand(arguments, no_stdout):
    # Fork process
    pid = fork()
    if pid:
        return pid

    # Child code
    try:
        ptrace_traceme()
    except PtraceError, err:
        print >>stderr, "CHILD PTRACE ERROR! %s" % err
        exit(1)
    for fd in xrange(3, MAXFD):
        try:
            close(fd)
        except OSError:
            pass
    if no_stdout:
        try:
            null = open(DEV_NULL_FILENAME , 'wb')
            dup2(null.fileno(), 1)
            dup2(1, 2)
            null.close()
        except IOError, err:
            close(2)
            close(1)
    try:
        execv(arguments[0], arguments)
    except OSError, err:
        print >>stderr, "CHILD EXECVE ERROR! %s" % err
        code = err.errno
    except Exception, err:
        print >>stderr, "CHILD EXECVE ERROR! %s" % err
        code = 1
    exit(code)

