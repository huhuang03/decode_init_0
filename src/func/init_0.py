from ..llvm_function import LlvmFunction
import angr

class Init0(LlvmFunction):
    def __init__(self, p: angr.Project) -> None:
        super().__init__("init_0", 0x754c, 0xb7b7, p)

    def debug_execute(self):
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
