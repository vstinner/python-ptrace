+++++++++++++++++++++
Process documentation
+++++++++++++++++++++


PtraceProcess
=============

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

