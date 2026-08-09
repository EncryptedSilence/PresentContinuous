# fw/m4/run.gdb -- load the ELF over st-util's gdb server and run it to completion.
#
# st-util 1.8.0 implements the semihosting write calls but not SYS_EXIT (it logs
# "unsupported call 0x18" and steps over it), so the target never stops on its
# own and a plain `continue; quit` would hang. Breaking at sh_exit -- reached
# only after the program has written everything it means to write -- is what
# ends the run. Any debugger that does honour SYS_EXIT behaves identically here.
target extended-remote :4242
monitor semihosting enable
load
break sh_exit
continue
quit
