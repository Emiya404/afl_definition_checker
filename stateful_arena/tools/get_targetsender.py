import gdb
import struct

class send_bp(gdb.Breakpoint):
    def __init__(self):
        super().__init__("__libc_send", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        sockfd = int(gdb.parse_and_eval("$rdi"))
        buf = int(gdb.parse_and_eval("$rsi"))
        length = int(gdb.parse_and_eval("$rdx"))
        flags = int(gdb.parse_and_eval("$rcx"))
        with open("./gdb_log", "a") as f:
            f.write(f"[*]libc send called with args:[{sockfd},{hex(buf)},{length},{hex(flags)}]\n")
        return False

class sendto_bp(gdb.Breakpoint):
    def __init__(self):
        super().__init__("__libc_sendto", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        sockfd = int(gdb.parse_and_eval("$rdi"))
        buf = int(gdb.parse_and_eval("$rsi"))
        length = int(gdb.parse_and_eval("$rdx"))
        flags = int(gdb.parse_and_eval("$rcx"))
        with open("./gdb_log", "a") as f:
            f.write(f"[*]libc sendto called with args:[{sockfd},{hex(buf)},{length},{hex(flags)}]\n")
        return False

class write_bp(gdb.Breakpoint):
    def __init__(self):
        super().__init__("__libc_write", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        fd = int(gdb.parse_and_eval("$rdi"))
        buf = int(gdb.parse_and_eval("$rsi"))
        length = int(gdb.parse_and_eval("$rdx"))
        with open("./gdb_log", "a") as f:
            f.write(f"[*]libc write called with args:[{fd},{hex(buf)},{length}]\n")
        return False

class fwrite_bp(gdb.Breakpoint):
    def __init__(self):
        super().__init__("fwrite", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        buf = int(gdb.parse_and_eval("$rdi"))
        size = int(gdb.parse_and_eval("$rsi"))
        num = int(gdb.parse_and_eval("$rdx"))
        filep = int(gdb.parse_and_eval("$rcx"))
        
        with open("./gdb_log", "a") as f:
            f.write(f"[*]libc fwrite called with args:[{hex(buf)},{size},{num},{hex(filep)}]\n")
        return False

class socket_end_bp(gdb.FinishBreakpoint):
    def __init__(self):
        super().__init__(gdb.newest_frame(), internal = True)
        self.silent = False

    def stop(self):
        retfd = int(gdb.parse_and_eval("$rax"))
        with open("./gdb_log", "a") as f:
            f.write(f"[*]socket fd is {retfd}\n")
        return False

class socket_bp(gdb.Breakpoint):
    def __init__(self):
        super().__init__("__socket", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        socket_end_bp();
        return False

class accept_end_bp(gdb.FinishBreakpoint):
    def __init__(self):
        super().__init__(gdb.newest_frame(), internal = True)
        self.silent = False

    def stop(self):
        retfd = int(gdb.parse_and_eval("$rax"))
        with open("./gdb_log", "a") as f:
            f.write(f"[*]derived TCP socket fd is {retfd}\n")
        return False

class accept_bp(gdb.Breakpoint):
    def __init__(self):
        super().__init__("accept", gdb.BP_BREAKPOINT, internal=False)
        self.silent = True

    def stop(self):
        accept_end_bp();
        return False
send_bp()
sendto_bp()
write_bp()
socket_bp()
accept_bp()
