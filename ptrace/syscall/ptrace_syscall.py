from os import strerror
from errno import errorcode

from ptrace.cpu_info import CPU_X86_64, CPU_POWERPC, CPU_I386, CPU_ARM32, CPU_AARCH64, CPU_RISCV
from ptrace.ctypes_tools import ulong2long, formatAddress, formatWordHex
from ptrace.func_call import FunctionCall
from ptrace.syscall import SYSCALL_NAMES, SYSCALL_PROTOTYPES, SyscallArgument
from ptrace.syscall.socketcall import setupSocketCall
from ptrace.os_tools import RUNNING_LINUX, RUNNING_BSD
from ptrace.cpu_info import CPU_WORD_SIZE
from ptrace.binding.cpu import CPU_INSTR_POINTER

if CPU_POWERPC:
    SYSCALL_REGISTER = "gpr0"
elif CPU_ARM32:
    SYSCALL_REGISTER = "r7"
elif CPU_AARCH64:
    SYSCALL_REGISTER = "r8"
elif CPU_RISCV:
    SYSCALL_REGISTER = "a7"
elif RUNNING_LINUX:
    if CPU_X86_64:
        SYSCALL_REGISTER = "orig_rax"
    else:
        SYSCALL_REGISTER = "orig_eax"
else:
    if CPU_X86_64:
        SYSCALL_REGISTER = "rax"
    else:
        SYSCALL_REGISTER = "eax"

if CPU_ARM32:
    RETURN_VALUE_REGISTER = "r0"
elif CPU_AARCH64:
    RETURN_VALUE_REGISTER = "r0"
elif CPU_I386:
    RETURN_VALUE_REGISTER = "eax"
elif CPU_X86_64:
    RETURN_VALUE_REGISTER = "rax"
elif CPU_POWERPC:
    RETURN_VALUE_REGISTER = "result"
elif CPU_RISCV:
    RETURN_VALUE_REGISTER = "a0"
else:
    raise NotImplementedError("Unsupported CPU architecture")

PREFORMAT_ARGUMENTS = {
    "select": (1, 2, 3),
    "execve": (0, 1, 2),
    "clone": (0, 1),
}


class PtraceSyscall(FunctionCall):

    def __init__(self, process, options, regs=None):
        FunctionCall.__init__(self, "syscall", options, SyscallArgument)
        self.process = process
        self.restype = "long"
        self.result = None
        self.result_text = None
        self.instr_pointer = None
        if not regs:
            regs = self.process.getregs()
        self.readSyscall(regs)

    def enter(self, regs=None):
        if not regs:
            regs = self.process.getregs()
        argument_values = self.readArgumentValues(regs)
        self.readArguments(argument_values)

        if self.name == "socketcall" and self.options.replace_socketcall:
            setupSocketCall(self, self.process, self[0], self[1].value)

        # Some arguments are lost after the syscall, so format them now
        if self.name in PREFORMAT_ARGUMENTS:
            for index in PREFORMAT_ARGUMENTS[self.name]:
                argument = self.arguments[index]
                argument.format()

        if self.options.instr_pointer:
            self.instr_pointer = getattr(regs, CPU_INSTR_POINTER)

    def readSyscall(self, regs):
        # Read syscall number
        self.syscall = getattr(regs, SYSCALL_REGISTER)
        # Get syscall variables
        self.name = SYSCALL_NAMES.get(
            self.syscall, "syscall<%s>" % self.syscall)

    def readArgumentValues(self, regs):
        if CPU_X86_64:
            return (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9)
        if CPU_ARM32:
            return (regs.r0, regs.r1, regs.r2, regs.r3, regs.r4, regs.r5, regs.r6)
        if CPU_AARCH64:
            return (regs.r0, regs.r1, regs.r2, regs.r3, regs.r4, regs.r5, regs.r6, regs.r7)
        if CPU_RISCV:
            return (regs.a0, regs.a1, regs.a2, regs.a3, regs.a4, regs.a5, regs.a6)
        if RUNNING_BSD:
            sp = self.process.getStackPointer()
            return [self.process.readWord(sp + index * CPU_WORD_SIZE)
                    for index in range(1, 6 + 1)]
        if CPU_I386:
            return (regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp)
        if CPU_POWERPC:
            return (regs.gpr3, regs.gpr4, regs.gpr5, regs.gpr6, regs.gpr7, regs.gpr8)
        raise NotImplementedError()

    def readArguments(self, argument_values):
        if self.name in SYSCALL_PROTOTYPES:
            self.restype, formats = SYSCALL_PROTOTYPES[self.name]
            for value, format in zip(argument_values, formats):
                argtype, argname = format
                self.addArgument(value=value, name=argname, type=argtype)
        else:
            for value in argument_values:
                self.addArgument(value=value)

    def exit(self):
        if self.name in PREFORMAT_ARGUMENTS:
            preformat = set(PREFORMAT_ARGUMENTS[self.name])
        else:
            preformat = set()

        # Data pointed by arguments may have changed during the syscall
        # e.g. uname() syscall
        for index, argument in enumerate(self.arguments):
            if index in preformat:
                # Don't lose preformatted arguments
                continue
            if argument.type and not argument.type.endswith("*"):
                continue
            argument.text = None

        self.result = self.process.getreg(RETURN_VALUE_REGISTER)

        if self.restype.endswith("*"):
            text = formatAddress(self.result)
        else:
            uresult = self.result
            self.result = ulong2long(self.result)
            if self.result < 0 and (-self.result) in errorcode:
                errcode = -self.result
                text = "%s %s (%s)" % (
                    self.result, errorcode[errcode], strerror(errcode))
            elif not(0 <= self.result <= 9):
                text = "%s (%s)" % (self.result, formatWordHex(uresult))
            else:
                text = str(self.result)
        self.result_text = text
        return text

    def __str__(self):
        return "<Syscall name=%r>" % self.name
