from ptrace.signames import signalName

class ProcessEvent(Exception):
    def __init__(self, process, message):
        Exception.__init__(self, message)
        self.process = process

class ProcessExit(ProcessEvent):
    def __init__(self, process, signum=None, exitcode=None):
        pid = process.pid
        if signum:
            message = "Process %s killed by signal %s" % (
                pid, signalName(signum))
        elif exitcode is not None:
            if not exitcode:
                message = "Process %s exited normally" % pid
            else:
                message = "Process %s exited with code %s" % (pid, exitcode)
        else:
            message = "Process %s terminated abnormally" % pid
        ProcessEvent.__init__(self, process, message)
        self.signum = signum
        self.exitcode = exitcode

class ProcessExecution(ProcessEvent):
    def __init__(self, process):
        ProcessEvent.__init__(self, process, "Process %s execution" % process.pid)

class NewProcessEvent(ProcessEvent):
    def __init__(self, process):
        ProcessEvent.__init__(self, process, "New process %s" % process.pid)

