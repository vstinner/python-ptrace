from ptrace.debugger.debugger import PtraceDebugger
from sys import stderr, argv, exit

def playWithProcess(process):
    print "== REGISTERS =="
    process.dumpRegs()

def main():
    # Get the process identifier
    if len(argv) != 2:
        print >>stderr, "usage: %s pid" % argv[0]
        exit(1)
    pid = int(argv[1])

    # Create the debugger and attach the process
    dbg = PtraceDebugger()
    process = dbg.tracePID(pid)

    # Play with the process and then quit
    playWithProcess(process)
    dbg.quit()

if __name__ == "__main__":
    main()

