"""
Mockup classes used in unit tests.
"""

class FakeProcess:
    def __init__(self):
        self.regs = {}

    def setreg(self, name, value):
        self.regs[name] = value

    def getreg(self, name):
        return self.regs[name]

