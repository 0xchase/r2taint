# r2taint

This plugin is still in development so may be buggy for you.

A plugin for radare2 that adds taint analysis using the Binary Analysis Platform (BAP) from CMU.

r2taint will highlight tainted instructions blue. Instructions tainted by mallocs are highlighted in red. 

---

![](example.gif)

---

## Command List
```
| T               Show the help
| Tr[?]           Propogate taint from register and mark tainted instructions
| Trc             Propogate taint from register and mark tainted calls
| Trl             List taints due to register
| Tr-             Remove taints due to register at current seek
| Tr--            Remove all taints due to register sources
| Tp[?]           Propogate taint from pointer and mark tainted instructions
| Tpc             Propogate taint from pointer and mark tainted calls
| Tpl             List taints due to register
| Tp-             Remove taints due to pointer
| Tp--            Remove all taints due to pointer sources
| Tm[?]           Propogate taint from mallocs and mark tainted instructions
| Tmc             Propogate taint from mallocs and mark tainted calls
| Tml             List taints from mallocs
| Tm-             Remove taints due to mallocs
| Tl              List all taint information
| T-              Remove all taint information
```

---

## Todo
 - Tv: Taint variables of current function or by name
 - Tg???: Various graphing commands for taint information
