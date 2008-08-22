from optparse import OptionGroup
from logging import (getLogger, StreamHandler,
    DEBUG, INFO, WARNING, ERROR)
from os import fork, execv, close, dup2
from sys import stderr, exit
from ptrace import PtraceError
from ptrace.binding import ptrace_traceme
from logging import error
from ptrace.tools import locateProgram
from ptrace.debugger import ProcessExit, DebuggerError
from errno import EPERM

class Application:
    def __init__(self):
        pass

    def _setupLog(self, fd):
        logger = getLogger()
        handler = StreamHandler(fd)
        logger.addHandler(handler)
        if self.options.debug:
            level = DEBUG
        elif self.options.verbose:
            level = INFO
        elif self.options.quiet:
            level = ERROR
        else:
            level = WARNING
        logger.setLevel(level)

    def processOptions(self):
        if self.program:
            self.program[0] = locateProgram(self.program[0])

    def createLogOptions(self, parser):
        log = OptionGroup(parser, "Logging")
        log.add_option("--quiet", "-q", help="Be quiet (set log level to ERROR)",
            action="store_true", default=False)
        log.add_option("--verbose", "-v", help="Debug mode (set log level to INFO)",
            action="store_true", default=False)
        log.add_option("--debug", help="Debug mode (set log level to DEBUG)",
            action="store_true", default=False)
        parser.add_option_group(log)

    def createChild(self, program):
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
        if self.options.no_stdout:
            try:
                null = open('/dev/null', 'w')
                dup2(null.fileno(), 1)
                del null
                dup2(1, 2)
            except IOError, err:
                close(2)
                close(1)
        try:
            execv(program[0], program)
        except OSError, err:
            print >>stderr, "CHILD EXECVE ERROR! %s" % err
            code = err.errno
        except Exception, err:
            print >>stderr, "CHILD EXECVE ERROR! %s" % err
            code = 1
        exit(code)

    def setupDebugger(self):
        # Set ptrace options
        if self.options.fork:
            try:
                self.debugger.traceFork()
            except DebuggerError:
                print >>stderr, "ERROR: --fork option is not supported by your OS, sorry!"
                exit(1)
        if self.options.trace_exec:
            self.debugger.traceExec()

    def createProcess(self):
        if self.options.pid:
            pid = self.options.pid
            is_attached = False
            error("Attach process %s" % pid)
        else:
            pid = self.createChild(self.program)
            is_attached = True
        try:
            return self.debugger.addProcess(pid, is_attached=is_attached)
        except (ProcessExit, PtraceError), err:
            if isinstance(err, PtraceError) \
            and err.errno == EPERM:
                error("ERROR: You are not allowed to trace process %s (permission denied or process already traced)" % pid)
            else:
                error("ERROR: Process can no be attached! %s" % err)
        return None

    def createCommonOptions(self, parser):
        parser.add_option("--pid", "-p", help="Attach running process specified by its identifier",
            type="int", default=None)
        parser.add_option("--fork", "-f", help="Trace fork and child process",
            action="store_true", default=False)
        parser.add_option("--trace-exec", help="Trace execve() event",
            action="store_true", default=False)
        parser.add_option("--no-stdout", help="Use /dev/null as stdout/stderr, or close stdout and stderr if /dev/null doesn't exist",
            action="store_true", default=False)

