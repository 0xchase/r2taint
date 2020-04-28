class BapTaint():
    def __init__(self):
        print("Created BapTaint object")

    def start(self):
        tainter = PropagateTaint("kindgoeshere")

class PropagateTaint():
    ENGINE="primus"
    DEPTH=4096
    LOOP_DEPTH=64

    def __init__(self, addr, kind):
        print("Created PropagateTaint object")
        addr = 0x400000
        value = "ptr"
        passes = "????"
        self.args += [
                "--taint-"+ value + hex(addr)
                "--passes " + ",".join(passes)

