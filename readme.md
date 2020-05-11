# r2taint
A plugin for radare2 that integrates the taint analysis capabilities of the Binary Analysis Platform (BAP) from CMU.

## Todo
 - Get bap-toolkit to install. Create commands for each interesting recipe.

 - Setup bap-ida-python, run BapIda.DEBUG=True to see what bap commands are being run
 - Figure out how proof script works. Script BAP to do stuff.
 - 

## Ideas
 - Highlight all instructions tained by some address
 - Highlight all syscall tainted by address
 - List functions tainted by user input
 - Search for memory leaking issues
 - Graph call taints
 - Can highlight taint by variable name
 - Can highlight taint by function argument
 - Add commands for all bap-toolkit tools

## Commands
 - Tm: Taint mallocs
 - Tmc: Trace taint between malloc and other system calls
 - Tml: List malloc taints
 - Tms: Seek to malloc taint
 - Ta: Taint at address
 - Tas: Taint between address and system calls

 - Something to taint arguments
 - Tr: Taint register at seek
 - Tp: Taint pointer at seek
 - Tv: Taint local variable by name
