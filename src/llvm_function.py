from networkx.algorithms.core import k_core
from .function import Func
import angr
from .import am_graph
import networkx
from . import util

class LlvmFunction(Func): 
    def __init__(self, name, start, end, p: angr.Project) -> None:
        super().__init__(name, start, end)
        self.prologue_node = None
        self.main_dispather_node = None
        self.pre_dispatch_node = None
        self.retn_node = None
        self.cfg = None
        self.supergraph: networkx.DiGraph = None
        self.relevant_ndoes = []
        self.nop_nodes = []
        self.p = p

    def initial(self):
        self.cfg = self.p.analyses.CFGFast(regions=[(self.start, self.end)], function_starts=[self.start + 1])

        target_function = self.cfg.functions.get(self.start+1)
        print(target_function)

        self.supergraph = am_graph.to_supergraph(target_function.transition_graph)
        print(self.supergraph)

        for n in self.supergraph.nodes():
            if self.supergraph.in_degree(n) == 0:
                if self.prologue_node is None:
                    self.prologue_node = n
                else:
                    print("Why has two prologue node: {}, {}".format(self.prologue_node, n))
            
            if self.supergraph.out_degree(n) == 0:
                if self.retn_node is None:
                    self.retn_node = n
                else:
                    print("Why has return prologue node: {}, {}".format(self.retn_node, n))

        assert(self.prologue_node is not None)
        assert(self.retn_node is not None)


        self.main_dispather_node = list(self.supergraph.successors(self.prologue_node))[0]

        print("prologue_node: {}".format(self.prologue_node))
        print("retn_node: {}".format(self.retn_node))
        print("main_dispatcher_node: {}".format(self.main_dispather_node))

        for n in self.supergraph.predecessors(self.main_dispather_node):
            if n.addr != self.prologue_node.addr:
                self.pre_dispatch_node = n
                break
        self.init_relevant_nop_nodes()

    def judge_is_sub_dispatcher(self, node: am_graph.SuperCFGNode):
        insts = self.p.factory.block(node.addr).capstone.insns
        if len(insts) == 4 and insts[0].mnemonic.startswith('mov') and\
            insts[1].mnemonic.startswith('mov') and\
            insts[2].mnemonic.startswith('cmp') and\
            util.mnemonic_is_jump(insts[3].mnemonic):
            print(f'sub_dispatchers: {node}')

    def find_relevant_node_by_relevant_node(self, node: am_graph.SuperCFGNode):
        """
        相关块的的前继，如果只有当前相关块这一个后继块，则认为也是相关块
        """
        for n in self.supergraph.predecessors(node):
            if len(list(self.supergraph.successors(n))) == 1:
                if not n in self.relevant_ndoes:
                    self.relevant_ndoes.append(n)
                    print(f'find relative relevant: {n}')

    def init_relevant_nop_nodes(self):
        # What' is a relevant node?
        for n in self.supergraph.predecessors(self.main_dispather_node):
            if not self.judge_is_sub_dispatcher(n):
                self.relevant_ndoes.append(n)
        self.init_relative_relevant_nodes()


    def init_relative_relevant_nodes(self):
        while True:
            previous_len = len(self.relevant_ndoes)
            for n in self.relevant_ndoes:
                self.find_relevant_node_by_relevant_node(n)
            if previous_len == len(self.relevant_ndoes):
                break

    def symbol_execute(self):
        def set_callless_to_state(s) -> bool: 
            # s.options.add(angr.sim_options.CALLLESS)
            return True

        start_s = self.p.factory.blank_state(addr=self.start + 1, option=[angr.sim_options.CALLLESS])
        sm: angr.SimulationManager = self.p.factory.simulation_manager(start_s)
        while True:
            sm.step(selector_func=set_callless_to_state)
            print(f'{sm.active}')
            print(f'{sm.active} pc: {sm.one_active.regs.pc}')
            if len(sm.active) <= 0:
                break