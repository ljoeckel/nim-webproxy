import std/[osproc, os]

proc execCmdWrap*(cmd: string): bool =
    ## Wrapper proc to catch errors when executing OS commands.
    if execCmd(cmd) != 0:
        echo "ERR [execCmdWrap] An error occured."
        false
    else:
        true
