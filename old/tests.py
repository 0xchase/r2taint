#!/usr/bin/python3

import bap
from IPython import embed
from bap_taint import *

def main():
    baptaint = BapTaint()
    exit()
    print("Running bap on hashmenot")
    proj = bap.run("hashmenot")
    print("Getting project")

    # Arguments
    arg = proj.arg
    attrs = proj.attrs
    constr = proj.constr
    memap = proj.memmap
    program = proj.program
    sections = proj.sections


def verify(prog, src_name, dst_name):
    src = prog.subs.find(src_name)
    dst = prog.subs.find(dst_name)

    if src is None or dst is None:
        print("Error: Src or dst not found")
        exit()

    graphs = GraphsBuilder()
    graphs.run(prog)
    cg = graphs.callgraph

    if nx.has_path(cg, src.id.number, dst.id.number):
        return ('calls', nx.shortest_path(cg, src.id.number, dst.id.number))

    calls = CallsitesCollector(graphs.callgraph, src.id.number, dst.id.number)

    for sub in prog.subs:
        calls.run(sub)
        cfg = graphs.callgraph.nodes[sub.id.number]['cfg']
        for src in calls.srcs:
            for dst in calls.dsts:
                if src != dst and nx.has_path(cfg, src, dst):
                    return ('sites', nx.shortest_path(cfg, src, dst))
        calls.clear()

    return None

main()
