from src.util.util_insn import insns_any_startsw_with
from networkx.algorithms.core import k_core
from .function import Func
import angr
from .import am_graph
import networkx
from . import util
from termcolor import colored
from .ex_node import ExNode

# bad name
def set_callless_to_state(s) -> bool: 
    s.options.add(angr.sim_options.CALLLESS)

    return True

class LlvmFunction(Func): 
    def __init__(self, name, start, end, p: angr.Project) -> None:
        super().__init__(name, start, end)
        self.prologue_node = None
        self.main_dispather_node = None
        self.retn_node = None
        self.cfg = None
        self.supergraph: networkx.DiGraph = None
        # this is relevant_nodes except main, retn
        self.relevant_nodes = []
        self.nop_nodes = []
        self.p = p

        # 在deflat之后应该保留的node
        self.keep_nodes = []
        self.keep_nodes_flow = []
        self.keep_ex_nodes = []

    def initial(self):
        self.cfg = self.p.analyses.CFGFast(regions=[(self.start, self.end)], function_starts=[self.start + 1])

        target_function = self.cfg.functions.get(self.start+1)
        print(target_function)

        self.supergraph = am_graph.to_supergraph(target_function.transition_graph)
        print(self.supergraph)
        # print(f'all noes: {list(self.supergraph.nodes())}')
        all_nodes = list(self.supergraph.nodes())
        sorted_nodes = sorted(all_nodes, key=lambda n: n.addr)
        print(sorted_nodes)

        for n in self.supergraph.nodes():
            if self.supergraph.in_degree(n) == 0:
                if self.prologue_node is None:
                    self.prologue_node = n
                else:
                    print("Why has two prologue node: {}, {}".format(self.prologue_node, n))
            
            if self.supergraph.out_degree(n) == 0:
                if not self.may_mistify_node(n):
                    if self.retn_node is None:
                        self.retn_node = n
                    else:
                        print("Why has two return node: {}, {}".format(self.retn_node, n))

        assert(self.prologue_node is not None)
        assert(self.retn_node is not None)


        self.main_dispather_node = list(self.supergraph.successors(self.prologue_node))[0]

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
                if not n in self.relevant_nodes:
                    self.relevant_nodes.append(n)
                    print(f'find relative relevant: {n}')

    def init_relevant_nop_nodes(self):
        # What' is a relevant node?
        for n in self.supergraph.predecessors(self.main_dispather_node):
            if not self.judge_is_sub_dispatcher(n):
                self.relevant_nodes.append(n)
        self.init_relative_relevant_nodes()

        print("prologue_node: {}".format(self.prologue_node))
        print("main_dispatcher_node: {}".format(self.main_dispather_node))
        print("retn_node: {}".format(self.retn_node))
        print(f'relevant nodes: {[hex(n.addr) for n in self.relevant_nodes]}')

        self.keep_nodes.append(self.prologue_node)
        self.keep_nodes.extend(self.relevant_nodes)
        self.keep_nodes.append(self.retn_node)

        self.relevant_nodes.append(self.prologue_node)
        self.relevant_nodes.append(self.main_dispather_node)
        self.relevant_nodes.append(self.retn_node)

        self.keep_ex_nodes = [ExNode(self.p, n) for n in self.keep_nodes]
        self.keep_ex_nodes = list(filter(lambda n: not n.is_mystery(), self.keep_ex_nodes))


    def may_mistify_node(self, n):
        """
        """
        insns = self.p.factory.block(n.addr).capstone.insns
        # util.node_print_insns(self.p, n)
        if util.insns_any_startsw_with(insns, 'add sp') and util.insns_any_startsw_with(insns,'nop') \
            and (not util.insns_any_startsw_with(insns, 'sub sp')):
            return True
        return False

    def init_relative_relevant_nodes(self):
        while True:
            previous_len = len(self.relevant_nodes)
            for n in self.relevant_nodes:
                self.find_relevant_node_by_relevant_node(n)
            if previous_len == len(self.relevant_nodes):
                break

    def is_state_return(self, state):
        return state.addr == self.retn_node.addr

    def get_state_list(self, s):
        history = s.history
        rst = []
        while history.parent is not None:
            rst.append(history.state)
            history = history.parent

        rst.reverse()
        return [p.__repr__() for p in rst]

    # def sample_execute_fist_active(state):
    #     # rst = []
    #     # cur_state = state.one_active
    
    def symbol_execute_always_choice_first(self):
        """
        return the execute flow
        """
        rst = []
        start_s = self.p.factory.blank_state(addr=self.start + 1, option=[angr.sim_options.CALLLESS])
        sm: angr.SimulationManager = self.p.factory.simulation_manager(start_s)

        while True:
            one_active = sm.one_active
            rst.append(one_active)
            print(one_active)
            if len(sm.active) > 0:
                sm.active = [one_active]
            if self.is_state_return(one_active):
                break
            sm.step(selector_func=set_callless_to_state)
        return rst

    def _symbol_execute_selector(self, state):
        state.options.add(angr.sim_options.CALLLESS)
        return not self.is_state_return(state)

    def _create_start_state(self):
        return self.p.factory.blank_state(addr=self.start + 1, option=[angr.sim_options.CALLLESS])

    def symbol_execute1(self):
        """
        """
        pending_s = []
        start_s = self._creat_init_state()

        pass

    def symbol_execute(self):
        """
        return the SimulationManager
        """
        orderd_inst = []
        orderd_inst.append(self.main_dispather_node)

        start_s = self._create_start_state()
        sm: angr.SimulationManager = self.p.factory.simulation_manager(start_s)

        while True:
            active = sm.active
            if all([self.is_state_return(s) for s in active]):
                print('We are done!!')
                break

            # if len(active) > 1:
            #     print(f'please handle active > 1. {sm.active}')
            
            # cur = sm.one_active
            # n = util.nodes_get_node_at(self.supergraph.nodes(), cur.addr)
            # if n is None:
            #     exit(f'why can\'t find node: {cur}')
            # print(f'execute at node: {n}')

            for s in sm.active:
                if s.addr == self.retn_node.addr:
                    print(colored(f'We got a return at index: {sm.active.index(s)}', 'green'))
                else:
                    node = util.nodes_get_node_at(self.keep_nodes, s.addr)
                    if node is not None:
                        self.keep_nodes_flow.append(node)

            sm.step(selector_func=self._symbol_execute_selector)

        return sm
