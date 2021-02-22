import os
from .func.jni_onload import JniOnLoad
import angr
from .project import Project
from .called_by_init_if_need import CalledByInitIfNeed
from src.func import jni_onload
from . import am_graph

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
    
# step_till_call_or_two_state(begin_s)
# now let's try 

proj = Project(p)

func_called_by_init_if_need = CalledByInitIfNeed()

# proj.step_till_call_or_two_state(func_called_by_init_if_need.creat_init_state(p))



# try defalt jni_on_load
jni_onload = JniOnLoad()

cfg = p.analyses.CFGFast(regions=[(jni_onload.start, jni_onload.end)], function_starts=[jni_onload.start + 1])

print(cfg)

target_function = cfg.functions.get(jni_onload.start+1)
print(target_function)

supergraph = am_graph.to_supergraph(target_function.transition_graph)
print(supergraph)

prologue_node = None
retn_node = None

for n in supergraph.nodes():
    if supergraph.in_degree(n) == 0:
        if prologue_node is None:
            prologue_node = n
        else:
            print("Why has two prologue node: {}, {}".format(prologue_node, n))
    
    if supergraph.out_degree(n) == 0:
        if retn_node is None:
            retn_node = n
        else:
            print("Why has return prologue node: {}, {}".format(retn_node, n))

assert(prologue_node is not None)
assert(retn_node is not None)


main_dispather_node = list(supergraph.successors(prologue_node))[0]

print("prologue_node: {}".format(prologue_node))
print("retn_node: {}".format(retn_node))
print("main_dispatcher_node: {}".format(main_dispather_node))
