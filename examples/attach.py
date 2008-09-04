from ptrace.debugger.debugger import PtraceDebugger
from sys import stderr, argv, exit

def playWithProcess(process):
    print "Dump process registers"
    process.dumpRegs()
    print "Continue process execution"
    process.cont()
    print "Wait next process event..."
    event = process.waitEvent()
    print "New process event: %s" % event

def main():
    # Get the process identifier
    if len(argv) != 2:
        print >>stderr, "usage: %s pid" % argv[0]
        exit(1)
    pid = int(argv[1])

    # Create the debugger and attach the process
    dbg = PtraceDebugger()
    process = dbg.addProcess(pid, False)

    # Play with the process and then quit
    playWithProcess(process)
    dbg.quit()

if __name__ == "__main__":
    main()

