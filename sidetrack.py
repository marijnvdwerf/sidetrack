import capstone
from capstone.x86 import *


class UnhandledArgumentException(Exception):
    pass


class UnhandledOpcodeException(Exception):
    pass


class InstructionFormatter:

    def format_register_operand(self, op: X86Op):
        labels = {
            X86_REG_AL: 'al',
            X86_REG_AH: 'ah',
            X86_REG_AX: 'ax',
            X86_REG_EAX: 'eax',

            X86_REG_BL: 'bl',
            X86_REG_BH: 'bh',
            X86_REG_BX: 'bx',
            X86_REG_EBX: 'ebx',

            X86_REG_CL: 'cl',
            X86_REG_CH: 'ch',
            X86_REG_CX: 'cx',
            X86_REG_ECX: 'ecx',

            X86_REG_DL: 'dl',
            X86_REG_DH: 'dh',
            X86_REG_DX: 'dx',
            X86_REG_EDX: 'edx',

            X86_REG_DI: 'di',
            X86_REG_EDI: 'edi',

            X86_REG_SI: 'si',
            X86_REG_ESI: 'esi',

            X86_REG_BP: 'bp',
            X86_REG_EBP: 'ebp',
        }

        label = labels.get(op.reg, None)
        if label is None:
            raise UnhandledArgumentException('Unhandled memory argument: %d' % op.reg)

        return 'emu.%s' % label

    def format_immutable_operand(self, op: X86Op):
        if op.imm < 10:
            return "{0:d}".format(op.imm)
        else:
            return "0x{0:X}".format(op.imm)

    def format_dest(self, op: X86Op):
        if op.type == X86_OP_REG:
            return self.format_register_operand(op)
        elif op.type == X86_OP_IMM:
            return self.format_immutable_operand(op)
        else:
            raise UnhandledArgumentException("unhandled argument type")

    def format_src(self, op: X86Op):
        if op.type == X86_OP_REG:
            return self.format_register_operand(op)
        elif op.type == X86_OP_IMM:
            return self.format_immutable_operand(op)
        else:
            raise UnhandledArgumentException("unhandled argument type")

    def format_push_op(self, ins: capstone.CsInsn):
        if (len(ins.operands) != 1):
            raise UnhandledArgumentException("unhandled argument count")

        op: X86Op = ins.operands[0]
        if op.type == X86_OP_REG and op.size == 4:
            return "emu.push(%s);" % self.format_register_operand(op)
        elif op.type == X86_OP_REG and op.size == 2:
            return "emu.push16(%s);" % self.format_register_operand(op)
        else:
            raise UnhandledArgumentException("unhandled argument type")

        return ""

    def format_ret_op(self, ins: capstone.CsInsn):
        # Should this also remove an item off the stack?
        return "return;".format(ins.mnemonic)

    def format_simple_op(self, ins: capstone.CsInsn):
        return "emu.{0}();".format(ins.mnemonic)

    def format_mov_op(self, ins: capstone.CsInsn):
        dest: X86Op = ins.operands[0]
        src: X86Op = ins.operands[1]
        if dest.type == X86_OP_REG and src.type == X86_OP_IMM:
            destStr = self.format_dest(dest)
            srcStr = self.format_src(src)
            return "{0} = {1};".format(destStr, srcStr)
        else:
            raise UnhandledArgumentException("unhandled argument type")

    def format(self, instruction: capstone.CsInsn) -> str:
        switch = {
            "push": self.format_push_op,
            "ret": self.format_ret_op,
            "mov": self.format_mov_op,

            "clc": self.format_simple_op,
            "cld": self.format_simple_op,
            "cmc": self.format_simple_op,
            "movsb": self.format_simple_op,
            "movsw": self.format_simple_op,
            "movsd": self.format_simple_op,
            "popfd": self.format_simple_op,
            "pushfd": self.format_simple_op,
            "std": self.format_simple_op,
            "popal": self.format_simple_op,
            "pushal": self.format_simple_op,
            "stc": self.format_simple_op,
        }

        fn = switch.get(instruction.mnemonic, None)
        if fn is None:
            raise UnhandledOpcodeException(instruction.mnemonic)

        return fn(instruction)
