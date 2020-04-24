#!/usr/bin/python3

import os

command = """
bap ./hashmenot --taint-reg=malloc_result \
       --run \
       --run-entry-points=entry0 \
       --primus-limit-max-length=4096 \
       --primus-promiscuous-mode \
       --primus-greedy-scheduler \
       --primus-propagate-taint-from-attributes \
       --primus-propagate-taint-to-attributes \
       --print-bir-attr=tainted-{ptrs,regs} \
       --dump=bir:result.out \
       --report-progress
"""

def main():
    os.system("rm result.out")
    os.system(command)
    results = ""
    with open("result.out", "r") as f:
        results = f.read()
    
    lines = []
    for line in results.split("\n"):
        if "sub" in line:
            lines.append(("="*20, "="*20))
        if len(line) > 1:
            addr = line.split(" ")[0].replace(":", "")
            inst = " ".join(line.split(" ")[1:])
            lines.append((addr, inst))
        else:
            lines.append(("", ""))

    for addr, line in lines:
        print(str(addr) + " : " + str(line))
main()
