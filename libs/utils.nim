import std/[osproc, strformat,
            os, times]
import parser
import strutils

let INTERACTIONS_D = "interactions"


proc execCmdWrap*(cmd: string): bool =
    ## Wrapper proc to catch errors when executing OS commands.
    ## Should add sanitization here.
    #log(lvlDebug, fmt"[execCmdWrap] running {cmd}.")
    if execCmd(cmd) != 0:
        echo "ERR [execCmdWrap] An error occured."
        false
    else:
        true


proc `$`(x: Header): string =
    for name, value in x.fieldPairs:
        let v = $value
        if not v.isEmptyOrWhitespace:
            result.add(name & ": " & v & "\n")


proc saveInteraction*(host: string, port: int, cid: string, src: string, dst: string): bool =
    let (src_header, src_body) = getBody(cid, src)
    let (dst_header, dst_body) = getBody(cid, dst)

    ## Saves an interaction to disk.
    let dirname = joinPath(INTERACTIONS_D, fmt"{host}-{port}")
    if not dirExists(INTERACTIONS_D): createDir(INTERACTIONS_D)
    if not dirExists(dirname): createDir(dirname)
    let dt = now()
    let timestamp = dt.format("yyyy-MM-dd-HH:mm:ss")
    try:
        var f = open(joinPath(dirname, fmt"{cid}-{timestamp}"), fmWrite)
        f.writeLine("Request")
        f.writeLine($src_header)
        #f.writeLine("")
        f.writeLine("Response")
        f.writeLine($dst_header)
        #f.writeLine("")
        f.writeLine("Body")
        f.write(dst_body)
        f.close()
    except: return false
    true
