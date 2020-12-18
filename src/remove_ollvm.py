import os
import angr

INIT_0_START = 0x754c
INIT_0_END = 0xb7b8

so_path = os.path.abspath("./out/libcms_removed_rubbilish1.so")

if not os.path.exists(so_path):
    exit(f"{so_path} not exist")

# p.arch = <Arch ARMEL (LE)>
p = angr.Project(so_path, load_options={"auto_load_libs": False}, main_opts={"base_addr": 0})

# stop at here. why?? why there are two function??
# ERROR   | 2020-12-16 15:32:05,607 | angr.analyses.cfg.cfg_fast | Decoding error occurred at address 0x754e of function 0x754e.
# ERROR   | 2020-12-16 15:32:05,619 | angr.analyses.cfg.cfg_fast | Decoding error occurred at address 0x754c of function 0x754c.
# cfg = p.analyses.CFGFast(regions=[(INIT_0_START, INIT_0_END)], function_starts=[INIT_0_START + 1])
# print(cfg)

# f = cfg.functions.get(INIT_0_END)
# print(f)
# print(dir(f))

s = p.factory.blank_state(addr=INIT_0_START+1)
print(s)
sm = p.factory.simulation_manager(s)
sm.step()
print(s)


# now let's try 