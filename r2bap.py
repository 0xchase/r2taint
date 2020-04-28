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
       --propagate-taint \
       --print-bir-attr=tainted-regs \
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

        print("Running r2bap")

        try:
            stdout, stderr = subprocess.Popen(["bap", "./hashmenot", "--taint-reg=malloc_result", "--llvm-base=0x400000", "--propagate-taint", "--print-bir-attr=tainted-regs", "-d", "--dump=bir:result.out"], stdout=subprocess.PIPE).communicate()

            lines = stdout.decode().split("\n")
            found = False
            for line in stdout.decode().split("\n"):
                if "sub main" in line:
                    found = True
                if "sub" in line and not "main" in line:
                    found = False
                if found:
                    if "taint" in line:
                        print(colored(line, "yellow"))
                    else:
                        print(line)

        except Exception as e:
            print(e)


        # Parse arguments
        #tmp = command.split(" ")
        #print(str(tmp))
        return 1

    return {"name": "r2bap",
            "licence": "GPLv3",
            "desc": "Integrates the taint analysis capabilities of BAP with radare2",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2bap):
    print("An error occurred while registering r2bap")

