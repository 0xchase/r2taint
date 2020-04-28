# r2taint
A plugin for radare2 that integrates the taint analysis capabilities of the Binary Analysis Platform (BAP) from CMU.

## Todo
 - Using test.py, go through entire API systematically. Understand how it all works. Make functions that print all the information possible

 - Setup bap-ida-python, run BapIda.DEBUG=True to see what bap commands are being run
 - Figure out how proof script works. Script BAP to do stuff.
 - 

## Ideas
 - Highlight all instructions tained by some address
 - Highlight all syscall tainted by address
 - List functions tainted by user input
 - Search for memory leaking issues
 - Graph call taints
