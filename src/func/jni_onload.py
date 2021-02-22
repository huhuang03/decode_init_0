from ..function import Func

class JniOnLoad(Func):
    def __init__(self) -> None:
        super().__init__("JniOnLoad", 0x04518, 0x49ef)
