import os
from .func.jni_onload import JniOnLoad
import angr
from .project import Project
from .called_by_init_if_need import CalledByInitIfNeed
from src.func import jni_onload
from . import am_graph
from .func.init_0 import Init0

so_path = os.path.abspath("./out/libcms_removed_rubbilish1.so")

if not os.path.exists(so_path):
    exit(f"{so_path} not exist")

# p.arch = <Arch ARMEL (LE)>
p = angr.Project(so_path, load_options={"auto_load_libs": False}, main_opts={"base_addr": 0})

proj = Project(p)

func_called_by_init_if_need = CalledByInitIfNeed()

# try defalt jni_on_load
# jni_onload = JniOnLoad(p)
# jni_onload.initial()
# jni_onload.symbol_execute()

init_0 = Init0(p)
init_0.initial()
init_0.symbol_execute()