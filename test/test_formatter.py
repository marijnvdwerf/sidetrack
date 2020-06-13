import unittest
import capstone
from sidetrack import InstructionFormatter

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
cs.detail = True

formatter = InstructionFormatter()


def convert(x86: bytes):
    disasm = cs.disasm(x86, 0)
    insn = next(disasm)

    return formatter.format(insn)


class TestAnswer(unittest.TestCase):

    def test_push_reg32(self):
        asm = b'\x52'  # push edx
        self.assertEqual(convert(asm), "emu.push(emu.edx);")

    def test_push_reg16(self):
        asm = b'\x66\x50'  # push ax
        self.assertEqual(convert(asm), "emu.push16(emu.ax);")
