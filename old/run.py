#!/usr/bin/python3

import os

command2 = """
bap ./hashmenot --taint-reg=malloc_result \
       --run \
       --run-entry-points=all-subroutines \
       --primus-limit-max-length=4096 \
       --primus-promiscuous-mode \
       --primus-greedy-scheduler \
       --primus-propagate-taint-from-attributes \
       --primus-propagate-taint-to-attributes \
       --print-bir-attr=tainted-{ptrs,regs} \
       --dump=bir:result.out \
       --report-progress
"""

command = """
bap ./hashmenot \
       --taint-reg=malloc_result \
       --propagate-taint \
       --print-bir-attr=tainted-regs \
       --print-bir-attr=address \
       -d \
       --dump=bir:result.out \
"""

command3 = """
      bap ./hashmenot --run \
              --run-entry-points=all-subroutines \
              --primus-limit-max-length=4096 \
              --llvm-base=0x400000 \
              --primus-promiscuous-mode \
              --primus-greedy-scheduler \
              --log-dir=results2.out \
              --print-bir-attr=tainted-{ptrs,regs} \
              --dump=bir:result.out \
              --report-progres

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
