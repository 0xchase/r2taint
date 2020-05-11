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
        elif cmd[0] == "Tr":
            try:
                taint_register(cmd[1])
            except Exception as e:
                print(e)
        elif cmd[0] == "Trc":
            try:
                taint_register_call(cmd[1])
            except Exception as e:
                print(e)
        elif cmd[0] == "Trl":
            try:
                for e in taints[r.cmd("s").strip("\n")]:
                    print(colored(e, "green") + ": " + r.cmd("CC. @ " + e).strip("\n"))
            except Exception as e:
                print(e)
        elif cmd[0] == "Tr-":
            try:
                for e in taints[r.cmd("s").strip("\n")]:
                    r.cmd("CC- @ " + e)
                    r.cmd("ecH- @ " + e)
                taints[r.cmd("s").strip("\n")] = []
            except Exception as e:
                print(e)
        elif cmd[0] == "Tr--":
            try:
                for key in taints:
                    if not key == "malloc":
                        for e in taints[key]:
                            r.cmd("CC- @ " + e)
                            r.cmd("ecH- @ " + e)
                        taints[key] = []
            except Exception as e:
                print(e)
        elif cmd[0] == "Tm":
            try:
                taint_malloc(cmd[1])
            except Exception as e:
                print(e)
        elif cmd[0] == "Tmc":
            try:
                taint_malloc_call(cmd[1])
            except Exception as e:
                print(e)
        elif cmd[0] == "Tml":
            try:
                for e in taints["malloc"]:
                    print(colored(e, "green") + ": " + r.cmd("CC. @ " + e).strip("\n"))
            except Exception as e:
                print(e)
        elif cmd[0] == "Tm-":
            try:
                for e in taints["malloc"]:
                    r.cmd("CC- @ " + e)
                    r.cmd("ecH- @ " + e)
                taints["malloc"] = []
            except Exception as e:
                print(e)
        elif cmd[0] == "T-":
            try:
                for key in taints:
                    for e in taints[key]:
                        r.cmd("CC- @ " + e)
                        r.cmd("ecH- @ " + e)
                    taints[key] = []
            except Exception as e:
                print(e)
        else:
            print(colored("Taint analysis commands using BAP", "yellow"))
            print("| Tm              " + colored("Propogate taint from mallocs and add comments at tainted instructions", "green"))
            print("| Tmc             " + colored("Propogate taint from mallocs and add comments only at tainted calls", "green"))
            print("| Tm-             " + colored("Remove taints due to mallocs", "green"))
            print("| Tml             " + colored("List taints from mallocs", "green"))
            print("| Tr              " + colored("Propogate taint from register at current seek and add comments at tainted instructions", "green"))
            print("| Trc             " + colored("Propogate taint from register at current seek and add comments only at tainted calls", "green"))
            print("| Tr-             " + colored("Remove taints due to register at current seek", "green"))
            print("| Tr--            " + colored("Remove all taints due to register sources", "green"))
            print("| Trl             " + colored("List taints due to register at current seek", "green"))
            print("| T-              " + colored("Remove all taint information", "green"))

        return 1

    def taint_highlight():
        print("Unimplemented")

    def taint_register_call(name):
        address = r.cmd("s").strip("\n")
        taints[address] = []
        found_taints = []
        print("Running BAP...")
        stdout, stderr = subprocess.Popen(
                ["bap", "./hashmenot", 
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
                    r.cmd("ecHi blue")
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
        print(colored("\nAdded comments at instructions tainted by register at " + last_address + "\n", "yellow"))

    def taint_register(name):
        address = r.cmd("s").strip("\n")
        taints[address] = []
        found_taints = []
        print("Running BAP...")
        stdout, stderr = subprocess.Popen(
                ["bap", "./hashmenot", 
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
                r.cmd("ecHi blue")
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
        print(colored("\nAdded comments at instructions tainted by register at " + last_address + "\n", "yellow"))

    def taint_malloc(name):
        print("Running BAP...")
        address = r.cmd("s").strip("\n")
        taints["malloc"] = []
        found_taints = []
        stdout, stderr = subprocess.Popen(
                ["bap", "./hashmenot", 
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
                r.cmd("ecHi red")
                r.cmd("CC-")
                r.cmd("CC " + reg + "tainted by malloc")
                taints["malloc"].append(last_address)
                print(colored(last_address, "green") + ": tainted by malloc")
        print(colored("\nAdded comments at instructions tainted by malloc\n", "yellow"))
        r.cmd("s " + address)

    def taint_malloc_call(name):
        print("Running BAP...")
        address = r.cmd("s").strip("\n")
        taints["malloc"] = []
        found_taints = []
        stdout, stderr = subprocess.Popen(
                ["bap", "./hashmenot", 
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
                    r.cmd("ecHi red")
                    r.cmd("CC-")
                    r.cmd("CC " + reg + "tainted by malloc")
                    taints["malloc"].append(last_address)
                    print(colored(last_address, "green") + ": tainted by malloc")
        print(colored("\nAdded comments at instructions tainted by malloc\n", "yellow"))
        r.cmd("s " + address)

    return {"name": "r2bap",
            "licence": "GPLv3",
            "desc": "Integrates the taint analysis capabilities of BAP with radare2",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2bap):
    print("An error occurred while registering r2bap")

