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
# hwo to config jump the data.
cfg = p.analyses.CFGFast(regions=[(INIT_0_START, INIT_0_END)], function_starts=[INIT_0_START + 1])
# print(cfg)

# f = cfg.functions.get(INIT_0_END)
# print(f)
# print(dir(f))

begin_s = p.factory.blank_state(addr=INIT_0_START+1, option=[angr.sim_options.CALLLESS])
# print(begin_s)
sm = p.factory.simulation_manager(begin_s)

# step to next block
# sm.step()
# print(begin_s)

def hook_call_method(f):
    # is there any better idea. find all jump method??
    pass

def set_callless_to_state(s) -> bool: 
    s.options.add(angr.sim_options.CALLLESS)
    return True

def step_till_call_or_two_state(init_state):
    sm = p.factory.simulation_manager(init_state)
    pre_s = None
    while len(sm.active) < 2:
        pre_s = sm.active
        print(pre_s)
        sm.step(selector_func=set_callless_to_state)
    print(sm.active)
    print(pre_s)
    
step_till_call_or_two_state(begin_s)
# now let's try 