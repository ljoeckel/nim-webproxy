import std/[nativesockets, strformat, logging, strutils, net, httpclient, sets, uri]
import system

const EASYLIST = "easylist.txt"
const CUSTOMLIST = "customlist.txt" 


proc getEasylist(filename: string): seq[string] =
    var easylist = ""
    try:
        # 1. check for local copy
        easylist = readFile(filename)
    except:
        if filename == EASYLIST:
            # 2. Get from network and save local copy
            var client = newHttpClient(sslContext=newContext(verifyMode=CVerifyPeer))
            defer: client.close()
            try:
                easylist = client.getContent("https://easylist.to/easylist/" & EASYLIST)
                writeFile(filename, easylist)
            except:
                log(lvlError, fmt"[getEasyList] Could not open {filename}. Exception:{getCurrentExceptionMsg()}")

    return splitLines(easylist)


proc processList(list: seq[string], hshset: var HashSet[string]) =
    for line in list:
        if line.startsWith("!"): 
            continue  # Ignore comments
        elif line.startsWith("||") and line.contains("^"): # domain blocking
            hshset.incl(line[2 .. line.rfind("^")-1])
        elif line.startsWith("http"): # exact address
            hshset.incl(line)
        elif line.startsWith("@@"): # positive list
            discard
        

proc getBlockedDomains*: HashSet[string] = 
    result = initHashSet[string]()

    # Append domains from Easylist
    processList(getEasylist(EASYLIST), result)
    # Append custom domains
    processList(getEasylist(CUSTOMLIST), result)