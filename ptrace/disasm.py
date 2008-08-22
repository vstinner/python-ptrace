try:
    from ptrace.cpu_info import CPU_I386, CPU_X86_64
    from ptrace.pydistorm import Decode
    if CPU_X86_64:
        from ptrace.pydistorm import Decode64Bits as DecodeBits
        MAX_INSTR_SIZE = 11
    elif CPU_I386:
        from ptrace.pydistorm import Decode32Bits as DecodeBits
        MAX_INSTR_SIZE = 8
    else:
        raise ImportError()
    from ptrace import PtraceError

    class Instruction:
        def __init__(self, instr):
            self.address = instr.offset
            self.size = instr.size
            self.mnemonic = str(instr.mnemonic)
            self.operands = str(instr.operands)
            self.hexa = str(instr.instructionHex)
            self.text = "%s %s" % (self.mnemonic, self.operands)

        def __str__(self):
            return self.text

    def disassemble(code, address=0x100):
        for instr in Decode(address, code, DecodeBits):
            yield Instruction(instr)

    def disassembleOne(code, address=0x100):
        for instr in disassemble(code, address):
            return instr
        raise PtraceError("Unable to disassemble %r" % code)

    HAS_DISASSEMBLER = True
except (ImportError, OSError):
    # OSError if libdistorm64.so doesn't exist
    HAS_DISASSEMBLER = False

