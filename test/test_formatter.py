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

    def test_mov_reg8_imm(self):
        asm = b'\xB4\x01'  # mov ah, 1
        self.assertEqual(convert(asm), "emu.ah = 1;")

    def test_mov_reg16_imm(self):
        asm = b'\x66\xBE\x1C\x00'  # mov si, 0x1c
        self.assertEqual(convert(asm), "emu.si = 0x1C;")

    def test_mov_reg32_imm(self):
        asm = b'\xB9\x00\x00\x00\x00'  # mov ecx, 0
        self.assertEqual(convert(asm), "emu.ecx = 0;")

    def test_mov_reg16_reg16(self):
        asm = b'\x66\x8B\xC2'  # mov ax, dx
        self.assertEqual(convert(asm), "emu.ax = emu.dx;")

    def test_pushal(self):
        asm = b'\x60'  # pushal
        self.assertEqual(convert(asm), "emu.pushal();")

    def test_popal(self):
        asm = b'\x61'  # popal
        self.assertEqual(convert(asm), "emu.popal();")

    def test_pushfd(self):
        asm = b'\x9C'  # pushfd
        self.assertEqual(convert(asm), "emu.pushfd();")

    def test_popfd(self):
        asm = b'\x9D'  # popfd
        self.assertEqual(convert(asm), "emu.popfd();")

    def test_movsb(self):
        asm = b'\xA4'  # movsb
        self.assertEqual(convert(asm), "emu.movsb();")

    def test_movsd(self):
        asm = b'\xA5'  # std
        self.assertEqual(convert(asm), "emu.movsd();")

    def test_movsw(self):
        asm = b'\x66\xA5'  # movsw
        self.assertEqual(convert(asm), "emu.movsw();")

    def test_ret(self):
        asm = b'\xC3'  # ret
        self.assertEqual(convert(asm), "return;")

    def test_cmc(self):
        asm = b'\xF5'  # cmc
        self.assertEqual(convert(asm), "emu.cmc();")

    def test_clc(self):
        asm = b'\xF8'  # clc
        self.assertEqual(convert(asm), "emu.clc();")

    def test_stc(self):
        asm = b'\xF9'  # stc
        self.assertEqual(convert(asm), "emu.stc();")

    def test_cld(self):
        asm = b'\xFC'  # cld
        self.assertEqual(convert(asm), "emu.cld();")

    def test_std(self):
        asm = b'\xFD'  # std
        self.assertEqual(convert(asm), "emu.std();")
