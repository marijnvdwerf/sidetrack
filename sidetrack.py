import capstone
from capstone.x86 import *


class UnhandledArgumentException(Exception):
    pass


class UnhandledOpcodeException(Exception):
    pass


class InstructionFormatter:

    def format_arg(self, op: X86Op):
        labels = {
            X86_REG_AX: 'ax',
            X86_REG_BP: 'bp',
            X86_REG_BX: 'bx',
            X86_REG_CX: 'cx',
            X86_REG_DX: 'dx',
            X86_REG_SI: 'si',
            X86_REG_EAX: 'eax',
            X86_REG_EBP: 'ebp',
            X86_REG_EBX: 'ebx',
            X86_REG_ECX: 'ecx',
            X86_REG_EDI: 'edi',
            X86_REG_EDX: 'edx',
            X86_REG_ESI: 'esi',
        }

        label = labels.get(op.reg, None)
        if label is None:
            raise UnhandledArgumentException('Unhandled memory argument: %d' % op.reg)

        return 'emu.%s' % label

    def format_push_op(self, ins: capstone.CsInsn):
        if (len(ins.operands) != 1):
            raise UnhandledArgumentException("unhandled argument count")

        op: X86Op = ins.operands[0]
        if op.type == X86_OP_REG and op.size == 4:
            return "emu.push(%s);" % self.format_arg(op)
        elif op.type == X86_OP_REG and op.size == 2:
            return "emu.push16(%s);" % self.format_arg(op)
        else:
            raise UnhandledArgumentException("unhandled argument type")

        return ""

    def format(self, instruction: capstone.CsInsn) -> str:
        switch = {
            "push": self.format_push_op
        }

        fn = switch.get(instruction.mnemonic, None)
        if fn is None:
            raise UnhandledOpcodeException(instruction.mnemonic)

        return fn(instruction)
