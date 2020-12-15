import barf
import os.path as path
from .comm import R_PUSH_END_1, cms, R_PUSH_START_1, R_PUSH_START_2
from .comm import *
import os

out_folder = os.path.join(os.getcwd(), "out")
if not os.path.exists(out_folder):
    os.mkdir(out_folder)

out_content = rubbish1.process(cms.content, cms.text_start, cms.text_end)
rubbish1.write(out_folder)

out_content = rubbish2.process(out_content, cms.text_start, cms.text_end)
rubbish2.write(out_folder)

out_path = os.path.join(out_folder, "libcms_removed_rubbilish1.so")
open(out_path, "wb").write(out_content)

# p = angr.Project(SO_PATH)
# # read the .text start and end

# print(p.arch)


# INIT_0_START = 0x754c

# so_barf = barf.BARF(SO_PATH)

# # print(so_barf)
# for addr, asm_instr, reil_instrs in so_barf.translate(INIT_0_START):
#     print("0x{addr:08x} {instr}".format(addr=addr, instr=asm_instr))
#     for reil_instr in reil_instrs:
#         print("{indent:11s} {instr}".format(indent="", instr=reil_instr))
# # cfg = so_barf.recover_cfg()
# # cfg.save("branch1_cfg")