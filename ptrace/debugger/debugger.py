from logging import info, warning
from ptrace import PtraceError
from os import waitpid, WNOHANG
from signal import SIGTRAP, SIGSTOP
from errno import ECHILD
from ptrace.debugger import PtraceProcess, ProcessSignal
from ptrace.binding import HAS_PTRACE_EVENTS
if HAS_PTRACE_EVENTS:
    from ptrace.binding.func import (
        PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK,
        PTRACE_O_TRACEEXEC, PTRACE_O_TRACESYSGOOD)

class DebuggerError(PtraceError):
    pass

class PtraceDebugger:
    def __init__(self):
        self.dict = {}   # pid -> PtraceProcess object
        self.list = []
        self.options = 0
        self.trace_fork = False
        self.trace_exec = False
        self.trace_sysgood = False
        self.traceSysgood()

    def addProcess(self, pid, is_attached, parent=None):
        """
        ptrace: Parent PtraceProcess() object
        """
        if pid in self.dict:
            raise KeyError("Process % is already registered!" % pid)
        process = PtraceProcess(self, pid, is_attached, parent=parent)
        info("Attach %s to debugger" % process)
        self.dict[pid] = process
        self.list.append(process)
        try:
            process.waitSignals(SIGTRAP, SIGSTOP)
        except KeyboardInterrupt:
            # Force attach without waiting for SIGTRAP or SIGSTOP signal
            pass
        except ProcessSignal, event:
            event.display()
        except:
            process.is_attached = False
            process.detach()
            raise
        if HAS_PTRACE_EVENTS and self.options:
            process.setoptions(self.options)
        return process

    def quit(self):
        info("Quit debugger")
        # Terminate processes in reverse order
        # to kill children before parents
        processes = list(self.list)
        for process in reversed(processes):
            process.terminate()
            process.detach()

    def _waitpid(self, wanted_pid, blocking=True):
        flags = 0
        if not blocking:
            flags |= WNOHANG
        if wanted_pid:
            if wanted_pid not in self.dict:
                raise DebuggerError("Unknown PID: %r" % wanted_pid, pid=wanted_pid)

            try:
                pid, status = waitpid(wanted_pid, flags)
            except OSError, err:
                if err.errno == ECHILD:
                    process = self[wanted_pid]
                    raise process.processTerminated()
                else:
                    raise err
        else:
            pid, status = waitpid(-1, flags)
        if (blocking or pid) and wanted_pid and (pid != wanted_pid):
            raise DebuggerError("Unwanted PID: %r (instead of %s)"
                % (pid, wanted_pid), pid=pid)
        return pid, status

    def _wait(self, wanted_pid, blocking=True):
        """
        Return None if there is no new event.
        """
        process = None
        while not process:
            pid, status = self._waitpid(wanted_pid, blocking)
            if not blocking and not pid:
                return None
            try:
                process = self.dict[pid]
            except KeyError:
                warning("waitpid() warning: Unknown PID %r" % pid)
        return process.processStatus(status)

    def waitProcessEvent(self, pid=None, blocking=True):
        return self._wait(pid, blocking)

    def waitSignals(self, *signals, **kw):
        """
        No signal means "any signal"
        """
        pid = kw.get('pid', None)
        while True:
            event = self._wait(pid)
            if event.__class__ != ProcessSignal:
                raise event
            signum = event.signum
            if signum in signals or not signals:
                return event
            raise event

    def waitSyscall(self, process=None):
        signum = SIGTRAP
        if self.trace_sysgood:
            signum |= 0x80
        if process:
            return self.waitSignals(signum, pid=process.pid)
        else:
            return self.waitSignals(signum)

    def deleteProcess(self, process=None, pid=None):
        if not process:
            try:
                process = self.dict[pid]
            except KeyError:
                return
        try:
            del self.dict[process.pid]
        except KeyError:
            pass
        try:
            self.list.remove(process)
        except ValueError:
            pass

    def traceFork(self):
        if not HAS_PTRACE_EVENTS:
            raise DebuggerError("Tracing fork events is not supported on this architecture or operating system")
        self.options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
        self.trace_fork = True
        info("Debugger trace forks (options=%s)" % self.options)

    def traceExec(self):
        if not HAS_PTRACE_EVENTS:
            # no effect on OS without ptrace events
            return
        self.trace_exec = True
        self.options |= PTRACE_O_TRACEEXEC

    def traceSysgood(self):
        if not HAS_PTRACE_EVENTS:
            # no effect on OS without ptrace events
            return
        self.trace_sysgood = True
        self.options |= PTRACE_O_TRACESYSGOOD

    def __getitem__(self, pid):
        return self.dict[pid]

    def __iter__(self):
        return iter(self.list)

    def __len__(self):
        return len(self.list)

