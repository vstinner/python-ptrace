+++++++++++++++++++
python-ptrace usage
+++++++++++++++++++

Hello World
===========

Short example attaching a running process. It gets the instruction pointer,
executes a single step, and gets the new instruction pointer::

    import ptrace.debugger
    import signal
    import subprocess
    import sys

    def debugger_example(pid):
        debugger = ptrace.debugger.PtraceDebugger()

        print("Attach the running process %s" % pid)
        process = debugger.addProcess(pid, False)
        # process is a PtraceProcess instance
        print("IP before: %#x" % process.getInstrPointer())

        print("Execute a single step")
        process.singleStep()
        # singleStep() gives back control to the process. We have to wait
        # until the process is trapped again to retrieve the control on the
        # process.
        process.waitSignals(signal.SIGTRAP)
        print("IP after: %#x" % process.getInstrPointer())

        process.detach()
        debugger.quit()

    def main():
        args = [sys.executable, '-c', 'import time; time.sleep(60)']
        child_popen = subprocess.Popen(args)
        debugger_example(child_popen.pid)
        child_popen.kill()
        child_popen.wait()

    if __name__ == "__main__":
        main()


API
===

PtraceProcess
-------------

The PtraceProcess class is an helper to manipulate a traced process.

Example::

    tracer = PtraceProcess(pid)              # attach the process
    tracer.singleStep()                      # execute one instruction
    tracer.cont()                            # continue execution
    tracer.syscall()                         # break at next syscall
    tracer.detach()                          # detach process

    # Get status
    tracer.getreg('al')                      # get AL register value
    regs = tracer.getregs()                  # read all registers
    bytes = tracer.readBytes(regs.ax, 10)    # read 10 bytes
    tracer.dumpCode()                        # dump code (as assembler or hexa is the disassembler is missing)
    tracer.dumpStack()                       # dump stack (memory words around ESP)

    # Modify the process
    shellcode = '...'
    ip = tracer.getInstrPointer()            # get EIP/RIP register
    bytes = tracer.writeBytes(ip, shellcode) # write some bytes
    tracer.setreg('ebx', 0)                  # set EBX register value to zero

Read ``ptrace/debugger/process.py`` source code to see more methods.

