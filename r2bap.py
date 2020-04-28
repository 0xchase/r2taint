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

    def process(command):
        global session
        global initialized

        """Process commands here"""

        if not command.startswith("n"):
            return 0

        if command == "nr":
            import bap
            proj = bap.run(binary)
            symbols = proj.attrs
            print(proj.program)
            return 1
        if command == "na":
            try:
                address = r.cmd("s")
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
                    if "taint" in line:
                        reg = line.split("{")[1].split("=")[0]
                        #print(colored(line, "yellow"))
                        r.cmd("s " + last_address)
                        r.cmd("CC-")
                        r.cmd("CC " + reg + "tainted by " + address)
                        print("Adding comment [" + line + "] at " + last_address)
                    else:
                        if "0x400" in line:
                            print(line.split("0x")[0] + colored("0x" + line.split("0x")[1], "green"))
                            pass
                        else:
                            print(line)
                            pass
            except Exception as e:
                print(e)
            r.cmd("s " + address)
            print("Added comments at instructions tainted by malloc")
        elif command == "nm":
            try:
                print("Running BAP...")
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
                    if "taint" in line:
                        reg = line.split("{")[1].split("=")[0]
                        #print(colored(line, "yellow"))
                        r.cmd("s " + last_address)
                        r.cmd("CC-")
                        r.cmd("CC " + reg + "tainted by malloc")
                        #print("Adding comment [" + line + "] at " + last_address)
                    else:
                        if "0x400" in line:
                            pass
                            #print(line.split("0x")[0] + colored("0x" + line.split("0x")[1], "green"))
                        else:
                            pass
            except Exception as e:
                print(e)
            print("Added comments at instructions tainted by malloc")
        else:
            print("Avaliable commands: nm")

        return 1

    return {"name": "r2bap",
            "licence": "GPLv3",
            "desc": "Integrates the taint analysis capabilities of BAP with radare2",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2bap):
    print("An error occurred while registering r2bap")

