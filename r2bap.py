#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe

"""
r2bap
"""

import r2lang
import r2pipe
import sys
import os
import subprocess
from termcolor import colored

r = r2pipe.open()

session = None
initialized = False

taint_command = """
bap ./hashmenot \
       --taint-reg=malloc_result \
       --primus-limit-max-length=4096 \
       --llvm-base=0x400000 \
       --primus-promiscuous-mode \
       --primus-greedy-scheduler \
       --propagate-taint \
       --print-bir-attr=tainted-{ptrs,regs} \
       --print-bir-attr=address \
       -d \
       --dump=bir:result.out \
"""

def r2bap(_):
    global session
    global initialized

    """Build the plugin"""

    binary = r.cmdj("ij")["core"]["file"]
    taints = {}

    def process(command):
        global session
        global initialized

        """Process commands here"""

        cmd = command.split(" ")

        if len(cmd) < 2:
            cmd.append(None)

        if not command.startswith("T"):
            return 0

        if cmd[0] == "Ti":
            import bap
            proj = bap.run(binary)
            symbols = proj.attrs
            print(proj.program)
            return 1
        elif cmd[0] == "Th":
            taint_highlight()
        elif cmd[0] == "Tp":
            taint_pointer(cmd[1])
        elif cmd[0] == "Tpc":
            taint_pointer_call(cmd[1])
        elif cmd[0] == "Tpl":
            try:
                for key in taints:
                    for e in taints[key]:
                        if "p" in key:
                            print(colored(e, "green") + ": " + r.cmd("CC. @ " + e).strip("\n"))
            except:
                pass
        elif cmd[0] == "Tp-":
            for e in taints[r.cmd("s").strip("\n") + "p"]:
                r.cmd("CC- @ " + e)
                r.cmd("ecH- @ " + e)
            taints[r.cmd("s").strip("\n") + "p"] = []
        elif cmd[0] == "Tr":
            taint_register(cmd[1])
        elif cmd[0] == "Trc":
            taint_register_call(cmd[1])
        elif cmd[0] == "Trl":
            try:
                for key in taints:
                    for e in taints[key]:
                        if not "p" in key and not "malloc" in key:
                            print(colored(e, "green") + ": " + r.cmd("CC. @ " + e).strip("\n"))
            except:
                pass
        elif cmd[0] == "Tr-":
            for e in taints[r.cmd("s").strip("\n")]:
                r.cmd("CC- @ " + e)
                r.cmd("ecH- @ " + e)
            taints[r.cmd("s").strip("\n")] = []
        elif cmd[0] == "Tr--":
            for key in taints:
                if not key == "malloc" and not "p" in key:
                    for e in taints[key]:
                        r.cmd("CC- @ " + e)
                        r.cmd("ecH- @ " + e)
                    taints[key] = []
        elif cmd[0] == "Tp--":
            for key in taints:
                if "p" in key:
                    for e in taints[key]:
                        r.cmd("CC- @ " + e)
                        r.cmd("ecH- @ " + e)
                    taints[key] = []
        elif cmd[0] == "Tm":
            taint_malloc(cmd[1])
        elif cmd[0] == "Tmc":
            taint_malloc_call(cmd[1])
        elif cmd[0] == "Tml":
            for e in taints["malloc"]:
                print(colored(e, "green") + ": " + r.cmd("CC. @ " + e).strip("\n"))
        elif cmd[0] == "Tm-":
            for e in taints["malloc"]:
                r.cmd("CC- @ " + e)
                r.cmd("ecH- @ " + e)
            taints["malloc"] = []
        elif cmd[0] == "T-":
            for key in taints:
                for e in taints[key]:
                    r.cmd("CC- @ " + e)
                    r.cmd("ecH- @ " + e)
                taints[key] = []
        elif cmd[0] == "Tl":
            try:
                for key in taints:
                    for e in taints[key]:
                        print(colored(e, "green") + ": " + r.cmd("CC. @ " + e).strip("\n"))
            except:
                pass
        else:
            print(colored("Taint analysis commands using BAP", "yellow"))
            temp = 0
            if "Tm" in cmd[0]:
                temp = 1
            elif "Tr" in cmd[0]:
                temp = 2
            elif "Tp" in cmd[0]:
                temp = 3

            if temp == 0 or temp == 2:
                print("| Tr"+colored("[?]", "yellow")+"           " + colored("Propogate taint from register and mark tainted instructions", "green"))
                if temp == 2:
                    print("| Trc             " + colored("Propogate taint from register and mark tainted calls", "green"))
                    print("| Trl             " + colored("List taints due to register", "green"))
                    print("| Tr-             " + colored("Remove taints due to register at current seek", "green"))
                    print("| Tr--            " + colored("Remove all taints due to register sources", "green"))

            if temp == 0 or temp == 3:
                print("| Tp"+colored("[?]", "yellow")+"           " + colored("Propogate taint from pointer and mark tainted instructions", "green"))
                if temp == 3:
                    print("| Tpc             " + colored("Propogate taint from pointer and mark tainted calls", "green"))
                    print("| Tpl             " + colored("List taints due to register", "green"))
                    print("| Tp-             " + colored("Remove taints due to pointer", "green"))
                    print("| Tp--            " + colored("Remove all taints due to pointer sources", "green"))

            if temp == 0 or temp == 1:
                print("| Tm"+colored("[?]", "yellow")+"           " + colored("Propogate taint from mallocs and mark tainted instructions", "green"))
                if temp == 1:
                    print("| Tmc             " + colored("Propogate taint from mallocs and mark tainted calls", "green"))
                    print("| Tml             " + colored("List taints from mallocs", "green"))
                    print("| Tm-             " + colored("Remove taints due to mallocs", "green"))

            if temp == 0:
                print("| Tl              " + colored("List all taint information", "green"))
                print("| T-              " + colored("Remove all taint information", "green"))

        rehighlight()

        return 1

    def rehighlight():
        for key in taints:
            for addr in taints[key]:
                r.cmd("ecH- @ " + addr)
        for key in taints:
            if "malloc" in key:
                for addr in taints[key]:
                    r.cmd("ecHi red @ " + addr)
            elif "p" in key:
                for addr in taints[key]:
                    r.cmd("ecHi blue @ " + addr)
            else:
                for addr in taints[key]:
                    r.cmd("ecHi blue @ " + addr)

    def taint_register_call(name):
        address = r.cmd("s").strip("\n")
        taints[address] = []
        found_taints = []
        print("Running BAP...")
        stdout, stderr = subprocess.Popen(
                ["bap", binary, 
                "--taint-reg=" + address,
                "--llvm-base=0x400000", 
                "--propagate-taint", 
                "--print-bir-attr=tainted-regs", 
                "--print-bir-attr=address",
                "-d", 
                "--dump=bir:result.out"], 
                stdout=subprocess.PIPE).communicate()

        lines = stdout.decode().split("\n")
        found = False
        last_address = ""

        for line in stdout.decode().split("\n"):
            if ".address" in line:
                last_address = line.split(" ")[1]
            if "taint" in line and not last_address in found_taints:
                reg = line.split("{")[1].split("=")[0]
                found_taints.append(last_address)
                r.cmd("s " + last_address)
                if "call" in r.cmd("pd 1"):
                    found = True
                    r.cmd("CC-")
                    taints[address].append(last_address)

                    if name == None:
                        r.cmd("CC " + reg + "tainted by " + address)
                    else:
                        r.cmd("CC " + reg + "tainted by " + name)
                    if name == None:
                        print(colored(last_address, "green") + ": tainted by register at " + address)
                    else:
                        print(colored(last_address, "green") + ": tainted by " + name)

        r.cmd("s " + address)
        if found:
            print(colored("\nAdded comments at instructions tainted by register at " + last_address + "\n", "yellow"))
        else:
            print(colored("No tainted calls found", "yellow"))

    def taint_register(name):
        address = r.cmd("s").strip("\n")
        taints[address] = []
        found_taints = []
        print("Running BAP...")
        stdout, stderr = subprocess.Popen(
                ["bap", binary, 
                "--taint-reg=" + address,
                "--llvm-base=0x400000", 
                "--propagate-taint", 
                "--print-bir-attr=tainted-regs", 
                "--print-bir-attr=address",
                "-d", 
                "--dump=bir:result.out"], 
                stdout=subprocess.PIPE).communicate()

        lines = stdout.decode().split("\n")
        found = False
        last_address = ""

        for line in stdout.decode().split("\n"):
            if ".address" in line:
                last_address = line.split(" ")[1]
            if "taint" in line and not last_address in found_taints:
                found = True
                found_taints.append(last_address)
                r.cmd("s " + last_address)
                r.cmd("CC-")
                taints[address].append(last_address)

                if name == None:
                    r.cmd("CC Tainted by " + address)
                else:
                    r.cmd("CC Tainted by " + name)
                if name == None:
                    print(colored(last_address, "green") + ": tainted by register at " + address)
                else:
                    print(colored(last_address, "green") + ": tainted by " + name)

        r.cmd("s " + address)
        if found:
            print(colored("\nAdded comments at instructions tainted by register at " + last_address + "\n", "yellow"))
        else:
            print(colored("No tainted instructions found", "yellow"))

    def taint_pointer(name):
        address = r.cmd("s").strip("\n")
        taints[address + "p"] = []
        found_taints = []
        print("Running BAP...")
        stdout, stderr = subprocess.Popen(
                ["bap", binary, 
                "--taint-ptr=" + address,
                "--llvm-base=0x400000", 
                "--propagate-taint", 
                "--print-bir-attr=tainted-ptrs", 
                "--print-bir-attr=address",
                "-d", 
                "--dump=bir:result.out"], 
                stdout=subprocess.PIPE).communicate()

        lines = stdout.decode().split("\n")
        found = False
        last_address = ""

        for line in stdout.decode().split("\n"):
            if ".address" in line:
                last_address = line.split(" ")[1]
            if "taint" in line and not last_address in found_taints:
                found = True
                found_taints.append(last_address)
                r.cmd("s " + last_address)
                r.cmd("CC-")
                taints[address + "p"].append(last_address)

                if name == None:
                    r.cmd("CC " + "Tainted by pointer at " + address)
                else:
                    r.cmd("CC " + "Tainted by " + name)
                if name == None:
                    print(colored(last_address, "green") + ": pointing at tainted value due to " + address)
                else:
                    print(colored(last_address, "green") + ": pointing at tainted value due to " + name)

        r.cmd("s " + address)
        if found:
            print(colored("\nAdded comments at instructions tainted by register at " + last_address + "\n", "yellow"))
        else:
            print(colored("No tainted instructions found", "yellow"))

    def taint_pointer_call(name):
        address = r.cmd("s").strip("\n")
        taints[address + "p"] = []
        found_taints = []
        print("Running BAP...")
        stdout, stderr = subprocess.Popen(
                ["bap", binary, 
                "--taint-ptr=" + address,
                "--llvm-base=0x400000", 
                "--propagate-taint", 
                "--print-bir-attr=tainted-ptrs", 
                "--print-bir-attr=address",
                "-d", 
                "--dump=bir:result.out"], 
                stdout=subprocess.PIPE).communicate()

        lines = stdout.decode().split("\n")
        found = False
        last_address = ""

        for line in stdout.decode().split("\n"):
            if ".address" in line:
                last_address = line.split(" ")[1]
            if "taint" in line and not last_address in found_taints:
                found_taints.append(last_address)
                r.cmd("s " + last_address)
                if "call" in r.cmd("pd 1"):
                    found = True
                    r.cmd("CC-")
                    taints[address + "p"].append(last_address)

                    if name == None:
                        r.cmd("CC " + "Tainted pointer from source " + address)
                    else:
                        r.cmd("CC " + "Tainted pointer from source " + name)
                    if name == None:
                        print(colored(last_address, "green") + ": pointing at tainted value due to " + address)
                    else:
                        print(colored(last_address, "green") + ": pointing at tainted value due to " + name)

        r.cmd("s " + address)
        if found:
            print(colored("\nAdded comments at instructions tainted by register at " + last_address + "\n", "yellow"))
        else:
            print(colored("No tainted calls found", "yellow"))

    def taint_malloc(name):
        print("Running BAP...")
        address = r.cmd("s").strip("\n")
        taints["malloc"] = []
        found_taints = []
        stdout, stderr = subprocess.Popen(
                ["bap", binary, 
                "--taint-reg=malloc_result", 
                "--llvm-base=0x400000", 
                "--propagate-taint", 
                "--print-bir-attr=tainted-regs", 
                "--print-bir-attr=address",
                "-d", 
                "--dump=bir:result.out"], 
                stdout=subprocess.PIPE).communicate()

        lines = stdout.decode().split("\n")
        found = False
        last_address = ""

        for line in stdout.decode().split("\n"):
            if ".address" in line:
                last_address = line.split(" ")[1]
            if "taint" in line and not last_address in found_taints:
                found = True
                found_taints.append(last_address)
                reg = line.split("{")[1].split("=")[0]
                r.cmd("s " + last_address)
                r.cmd("CC-")
                r.cmd("CC Tainted by malloc")
                taints["malloc"].append(last_address)
                print(colored(last_address, "green") + ": tainted by malloc")
        if found:
            print(colored("\nAdded comments at instructions tainted by malloc\n", "yellow"))
        else:
            print(colored("No tainted instructions found", "yellow"))
        r.cmd("s " + address)

    def taint_malloc_call(name):
        print("Running BAP...")
        address = r.cmd("s").strip("\n")
        taints["malloc"] = []
        found_taints = []
        stdout, stderr = subprocess.Popen(
                ["bap", binary, 
                "--taint-reg=malloc_result", 
                "--llvm-base=0x400000", 
                "--propagate-taint", 
                "--print-bir-attr=tainted-regs", 
                "--print-bir-attr=address",
                "-d", 
                "--dump=bir:result.out"], 
                stdout=subprocess.PIPE).communicate()

        lines = stdout.decode().split("\n")
        found = False
        last_address = ""

        for line in stdout.decode().split("\n"):
            if ".address" in line:
                last_address = line.split(" ")[1]
            if "taint" in line and not last_address in found_taints:
                found_taints.append(last_address)
                reg = line.split("{")[1].split("=")[0]
                r.cmd("s " + last_address)
                if "call" in r.cmd("pd 1"):
                    found = True
                    r.cmd("CC-")
                    r.cmd("CC Tainted by malloc")
                    taints["malloc"].append(last_address)
                    print(colored(last_address, "green") + ": tainted by malloc")
        if found:
            print(colored("\nAdded comments at instructions tainted by malloc\n", "yellow"))
        else:
            print(colored("No tainted calls found", "yellow"))
        r.cmd("s " + address)

    return {"name": "r2bap",
            "licence": "GPLv3",
            "desc": "Integrates the taint analysis capabilities of BAP with radare2",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2bap):
    print("An error occurred while registering r2bap")

