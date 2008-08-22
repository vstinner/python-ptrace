from logging import error
from ptrace.disasm import HAS_DISASSEMBLER
from signal import SIGFPE, SIGCHLD, SIGSEGV, SIGBUS, SIGABRT
from ptrace.os_tools import RUNNING_LINUX
from ptrace.cpu_info import CPU_64BITS
from ptrace.debugger import ProcessEvent
from ptrace.error import PtraceError
from ptrace import signalName
from ptrace.debugger.signal_reason import (
    DivisionByZero, Abort, StackOverflow,
    InvalidMemoryAcces, InvalidRead, InvalidWrite,
    InstructionError, ChildExit)
import re

# Match a pointer dereference (eg. "DWORD [EDX+0x8]")
DEREF_REGEX = r'(?:(BYTE|WORD|DWORD|DQWORD) )?\[([^]]+)\]'

NAMED_WORD_SIZE = {
    'BYTE': 1,
    'WORD': 2,
    'DWORD': 4,
    'DQWORD': 8,
}

# Match any Intel instruction (eg. "ADD")
INSTR_REGEX = '(?:[A-Z]{3,10})'

def findDerefSize(match):
    name = match.group(1)
    try:
        return NAMED_WORD_SIZE[name]
    except KeyError:
        return None

class ProcessSignal(ProcessEvent):
    def __init__(self, signum, process):
        # Initialize attributes
        self.name = signalName(signum)
        ProcessEvent.__init__(self, process, "Signal %s" % self.name)
        self.signum = signum
        self.reason = None

    def _analyze(self):
        if self.signum in (SIGSEGV, SIGBUS):
            self.memoryFault()
        elif self.signum == SIGFPE:
            self.mathError()
        elif self.signum == SIGCHLD:
            self.childExit()
        elif self.signum == SIGABRT:
            self.reason = Abort()
        return self.reason

    def getInstruction(self):
        if not HAS_DISASSEMBLER:
            return None
        try:
            return self.process.disassembleOne()
        except PtraceError:
            return None

    def memoryFaultInstr(self, instr, fault_address):
        asm = instr.text

        # Invalid write (eg. "MOV [...], value")
        match = re.search(r"^(?:MOV|TEST)[A-Z]* %s," % DEREF_REGEX, asm)
        if match:
            self.reason = InvalidWrite(fault_address, size=findDerefSize(match),
                instr=instr, process=self.process)
            return

        # Invalid read (eg. "CMP BYTE [EAX+EDX-0x1], 0x0")
        match = re.search(r"^%s %s," % (INSTR_REGEX, DEREF_REGEX), asm)
        if match:
            self.reason = InvalidRead(fault_address, size=findDerefSize(match),
                instr=instr, process=self.process)
            return

        # Invalid read (eg. "MOV reg, [...]")
        match = re.match(r"%s [^,]+, %s" % (INSTR_REGEX, DEREF_REGEX), asm)
        if match:
            self.reason = InvalidRead(fault_address, size=findDerefSize(match),
                instr=instr, process=self.process)
            return

        # MOVS* instructions (eg. "MOVSB" or "REP MOVSD")
        match = re.search(r"^(?:REP )?MOVS([BWD])?", asm)
        if match:
            suffix = match.group(1)
            size = {'B': 1, 'W': 2, 'D': 4}.get(suffix)
            error_cls = InvalidMemoryAcces
            try:
                if CPU_64BITS:
                    di = self.process.getreg('rdi')
                    si = self.process.getreg('rsi')
                    registers = {'rdi': di, 'rsi': si}
                else:
                    di = self.process.getreg('edi')
                    si = self.process.getreg('esi')
                    registers = {'edi': di, 'esi': si}
                if fault_address is not None:
                    if fault_address == di:
                        error_cls = InvalidRead
                    elif fault_address == si:
                        error_cls = InvalidWrite
                else:
                    fault_address = (di, si)
            except PtraceError:
                registers = {}
            self.reason = error_cls(fault_address, size=size, instr=instr,
                registers=registers, process=self.process)
            return

    def getSignalInfo(self):
        if RUNNING_LINUX:
            return self.process.getsiginfo()
        else:
            return None

    def memoryFault(self):
        # Get fault
        siginfo = self.getSignalInfo()
        if siginfo:
            fault_address = siginfo._sigfault._addr
            if not fault_address:
                 fault_address = 0
        else:
             fault_address = None

        # Get current instruction
        instr = self.getInstruction()

        # Call to invalid address?
        if fault_address is not None:
            try:
                ip = self.process.getInstrPointer()
                if ip == fault_address:
                    self.reason = InstructionError(ip, process=self.process)
                    return
            except PtraceError:
                pass

        # Stack overflow?
        stack = self.process.findStack()
        if stack:
            sp = self.process.getStackPointer()
            if not (stack.start <= sp <= stack.end):
                self.reason = StackOverflow(sp, stack, instr=instr, process=self.process)
                return

        # Guess error type using the assembler instruction
        if instr:
            self.memoryFaultInstr(instr, fault_address)
            if self.reason:
                return

        # Last chance: use generic invalid memory access error
        if fault_address is not None:
            self.reason = InvalidMemoryAcces(fault_address, instr=instr, process=self.process)

    def mathError(self):
        instr = self.getInstruction()
        if not instr:
            return
        match = re.match(r"I?DIV (.*)", instr.text)
        if not match:
            return
        self.reason = DivisionByZero(instr=instr, process=self.process)

    def childExit(self):
        siginfo = self.getSignalInfo()
        if siginfo:
            child = siginfo._sigchld
            self.reason = ChildExit(child.pid, child.status, child.uid)
        else:
            self.reason = ChildExit()

    def display(self, log=None):
        self._analyze()
        if not log:
            log = error
        log("-" * 60)
        log("PID: %s" % self.process.pid)
        log("Signal: %s" % self.name)
        if self.reason:
            self.reason.display(log)
        log("-" * 60)

