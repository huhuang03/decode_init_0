import os
import os.path as path
import barf

SO_PATH = path.join(path.dirname(path.abspath(__file__)), "libcms.so")

INIT_0_START = 0x754c

if not path.exists(SO_PATH):
    exit("N")

so_barf = barf.BARF(SO_PATH)

# print(so_barf)
for addr, asm_instr, reil_instrs in so_barf.translate(INIT_0_START):
    print("0x{addr:08x} {instr}".format(addr=addr, instr=asm_instr))
    for reil_instr in reil_instrs:
        print("{indent:11s} {instr}".format(indent="", instr=reil_instr))
# cfg = so_barf.recover_cfg()
# cfg.save("branch1_cfg")