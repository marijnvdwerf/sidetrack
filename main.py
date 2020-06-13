#!/usr/bin/env python3
import os
from typing import TextIO

import capstone
import idb
import idb.analysis
from capstone import CsInsn

from sidetrack import InstructionFormatter


def FuncItems(db: idb.IDAPython, ea):
    func = db.ida_funcs.get_func(ea)

    addr = func.startEA
    while addr < func.endEA:
        yield addr
        addr = db.idc.NextHead(addr)


success = 0
failures = 0

mnemFiles = {}


def renderFunction(db: idb.IDAPython, cs: capstone.Cs, fnEa: int):
    global failures, success
    func = db.ida_funcs.get_func(fnEa)

    bytes = db.idc.GetManyBytes(func.startEA, func.endEA - func.startEA)

    formatter = InstructionFormatter()

    instruction: CsInsn
    for instruction in cs.disasm(bytes, func.startEA):
        # for ea in FuncItems(db, fnEa):
        flags = db.idc.GetFlags(instruction.address)
        if (flags & 0x00000600) != 0x00000600:
            # not code
            print("Early escape {0:x}\n".format(instruction.address))
            return

        try:
            formatted = formatter.format(instruction)
            success = success + 1
        except:
            failures = failures + 1

            fh: TextIO
            if mnemFiles.get(instruction.mnemonic) is None:
                fh = open('out/{0}.txt'.format(instruction.mnemonic), 'w')
                mnemFiles[instruction.mnemonic] = fh
            fh = mnemFiles.get(instruction.mnemonic)
            fh.write("{0} {1}\n".format(instruction.mnemonic, instruction.op_str))

    return


def main():
    if not os.path.exists("out"):
        os.makedirs("out")

    db: idb.fileformat.IDB
    with idb.from_file('../loco-temp/loco.i64') as db:
        api = idb.IDAPython(db)
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True

        for ea, func in idb.analysis.Functions(db).functions.items():
            if (ea < 0x4083AC) or (ea > 0x4CFF1E):
                continue
            if idb.analysis.is_flag_set(func.flags, func.FUNC_TAIL):
                continue
            renderFunction(api, cs, ea)

        total = failures + success
        print("Failures:  {0} ({1}%)\n".format(failures, failures / total * 100))
        print("Successes: {0} ({1}%)\n".format(success, success / total * 100))


if __name__ == '__main__':
    main()
