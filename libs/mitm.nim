import std/[algorithm, sequtils, asyncnet, asyncdispatch, nativesockets,
            strutils,
            net, tables, sets, oids,  math, streams]
import system
import parser, reader, certman, utils
import easylist
#import watchout
import statcounter

const 
    BUFF_SIZE = 2048
    BLOCK_ADS = false
    SAVE_INTERACTION = false
    BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
    OK = "HTTP/1.1 200 OK\r\n\r\n"
    NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
    NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"
      
var
    BUFFER_MAP = initTable[string, StringStream]()
    HEADER_MAP = initTable[string, Header]()
    SOCKET_MAP = initTable[string, AsyncSocket]()
    REMOTE_SOCKET_MAP = initTable[string, AsyncSocket]()
    BLOCKED_DOMAINS: HashSet[string]


proc removeSocket(cid: string) =
    incrementCounter("REMOVE_SOCKET")
    if SOCKET_MAP.hasKey(cid):
        incrementCounter("SOCKET_MAP.close")
        SOCKET_MAP[cid].close()
        SOCKET_MAP.del(cid)

    if REMOTE_SOCKET_MAP.hasKey(cid):
        incrementCounter("SOCKET_MAP_REMOTE.close")
        REMOTE_SOCKET_MAP[cid].close()
        REMOTE_SOCKET_MAP.del(cid)

    setCounter("SOCKET_MAP.len", len(SOCKET_MAP))
    setCounter("SOCKET_MAP_REMOTE.len", len(REMOTE_SOCKET_MAP))


proc sendRawRequest(target: AsyncSocket, 
                    req: string): Future[tuple[headers: string, 
                                               body: string]] {.async.} =
    ## This proc sends the given raw HTML request (req) through the given socket (target).
    ## Returns a future tuple containing the headers an body of the response.
    incrementCounter("RAW_REQUEST")
    await target.send(req)
    if req.startsWith("HEAD") or req.startsWith("TRACE"):
        result = await target.readHTTPRequest(body=false)
    else:
        result = await target.readHTTPRequest()


proc tunnel(src: AsyncSocket, dst: AsyncSocket, cid: string): Future[(string, string)] {.async.} =
    let keyS = cid & ":S"
    let keyD = cid & ":D"

    defer: 
        removeSocket(cid)
        BUFFER_MAP[keyS].close()
        BUFFER_MAP.del(keyS)
        HEADER_MAP.del(keyS)

        BUFFER_MAP[keyD].close()
        BUFFER_MAP.del(keyD)
        HEADER_MAP.del(keyD)

        setCounter("BUFFER_MAP.len", len(BUFFER_MAP))    
        setCounter("HEADER_MAP.len", len(HEADER_MAP))    

    proc srcHasData(): Future[string] {.async.}  =
        var buf = newStringStream()

        defer:
            BUFFER_MAP[keyS] = buf
            incrementCounter("SRC.future.complete")

        try:
            while not src.isClosed and not dst.isClosed:
                let data = src.recv(BUFF_SIZE)
                let future = await withTimeout(data, 1000)
                if future and not dst.isClosed and data.read.len() != 0:
                    let s = data.read()
                    incrementCounter("TUNNEL_SRC", len(s), StatType.bytes )
                    if buf.getPosition() == 0:
                        HEADER_MAP[keyS] = getHeader(cid, s)
                    buf.write(s)
                    await dst.send(removeEncoding(s))
                else:
                    break
        except:
            incrementCounter("SRC_HAS_DATA ERR")
            echo "ERR! src.hasData ", getCurrentExceptionMsg()


    proc dstHasData(): Future[string] {.async.} =
        var buf = newStringStream("")

        defer:
            BUFFER_MAP[keyD] = buf
            incrementCounter("DST.future.complete")

        try:
            while not dst.isClosed and not src.isClosed:
                let data = dst.recv(BUFF_SIZE)
                let future = await withTimeout(data, 1000)
                if future and not src.isClosed and data.read.len() != 0:
                    let s = data.read()
                    incrementCounter("TUNNEL_DST", len(s), StatType.bytes )
                    if buf.getPosition() == 0:
                        HEADER_MAP[keyD] = getHeader(cid, s)
                    buf.write(s)
                    await src.send(s)
                else:
                    break
        except:
            incrementCounter("DST_HAS_DATA ERR")
            echo "ERR! dstHasData", getCurrentExceptionMsg()


    await srcHasData() and dstHasData()

    try:
        let buf_src = BUFFER_MAP[keyS]
        buf_src.setPosition(0)
        let src = buf_src.readAll()

        let buf_dst = BUFFER_MAP[keyD]
        buf_dst.setPosition(0)
        let dst = buf_dst.readAll()

        if HEADER_MAP.hasKey(keyD):
            let header = HEADER_MAP[keyD]
            if header.hasContent:
                echo "DST cid:", header.cid, " type:", header.content_type," encoding:", header.content_encoding, " len:", header.content_length, " status_code:", header.response_status_code
                let body = getBody(header, dst)
                if header.content_encoding.isEmptyOrWhitespace:
                    echo body[0..min(80,len(body)-1)]

        else:
            if HEADER_MAP.hasKey(keyS):
                echo "HEADER:S ", HEADER_MAP[keyS]

        return (src, dst)
    except:
        incrementCounter("STREAM_READALL_ERR")
        echo "streeam.readAll " & getCurrentExceptionMsg()
        return ("", "")


proc mitmHttp(client: AsyncSocket, 
              host: string, port: int, 
              req: string, cid: string): Future[(string, string)] {.async.} = 
    ## Man in the Middle a given connection to its desired destination.
    ## For HTTP, we simply forward the request and save the response.
    ## Returns the interaction, containing the request and response in full.
    
    let remote = newAsyncSocket(buffered=false)
    REMOTE_SOCKET_MAP[cid] = remote
    defer:
        removeSocket(cid)

    try:
        await remote.connect(host, Port(port))
        var res_info = await remote.sendRawRequest(removeEncoding(req))
        await client.send(res_info.headers & res_info.body)
        return (req & "\r\n", res_info.headers & res_info.body)
    except:
        incrementCounter("HTTP_RESOLVE_HOST")
        echo "http Could not resolve remote host " & host
        await client.send(NOT_FOUND)


proc mitmHttps(client: AsyncSocket, host: string, port: int, cid: string): Future[(string, string)] {.async.} =
    ## Man in the Middle a given connection to its desired destination.
    ## For HTTPS, we negotiate ssl on the given client socket.
    ## Then we connect to the desired destination with the right ssl context.
    ## Finally, we tunnel these two sockets together while saving the data in between.
    ## Returns the interaction, containing the request and response in full.
    
    result = ("", "")
    defer:
        removeSocket(cid)

    if not handleHostCertificate(host):
        incrementCounter("HANDLE_HOST_CERTIFICATE")
        echo "Error occured while generating certificate for {host}."
        await client.send(BAD_REQUEST)
        return
    
    let remote = newAsyncSocket(buffered=false)
    REMOTE_SOCKET_MAP[cid] = remote
    let remote_ctx = newContext(verifyMode = CVerifyNone)
    defer:
        remote_ctx.destroyContext()

    wrapSocket(remote_ctx, remote)
    
    try:
        await remote.connect(host, Port(port))
    except:
        echo "https ERR Could not resolve remote host", $host
        incrementCounter("RESOLVE_HOST_ERR")
        await client.send(NOT_FOUND)
        return
    
    try:
        await client.send(OK)
    except:
        incrementCounter("CLIENT_SEND")
        echo "ERR Could not send to client"
        return

    let ctx = getMITMContext(host)
    defer: 
        ctx.destroyContext()

    wrapConnectedSocket(ctx, client, handshakeAsServer, hostname = host)

    try:
        result = await tunnel(client, remote, cid)
        echo "buffer_map.len:", len(BUFFER_MAP), " header_map.len:", len(HEADER_MAP)
    except:
        incrementCounter("TUNNEL_ERR")
        echo "Error tunnel cid=", cid, repr(remote)
    

proc processClient(client: AsyncSocket, cid: string) {.async.} =
    defer:
        removeSocket(cid)

    incrementCounter("REQUESTS")

    let req = await readHTTPRequest(client)
    var headers = parseHeaders(req.headers)

    var requestline = headers.getOrDefault("requestline", "").split(" ")
    if requestline == @[""]:
        incrementCounter("EMPTY_REQUESTLINE")
        await client.send(BAD_REQUEST)
        return
    
    var (proto, host, port, route) = parseProxyHost(requestline[1])
    
    if host == "":
        incrementCounter("EMPTY_HOST")
        await client.send(BAD_REQUEST)
        return

    if BLOCK_ADS:
        # Lookup full hostname in BLOCKED_DOMAIN
        if BLOCKED_DOMAINS.contains(host): 
            incrementCounter("BLOCKED_DOMAINS")
            await client.send(BAD_REQUEST)
            return

        # Extract domainname from host
        let domain = join(host.split(".")[^2 .. ^1], ".")
        if BLOCKED_DOMAINS.contains(domain): 
            incrementCounter("BLOCKED_DOMAINS")
            await client.send(BAD_REQUEST)
            return
    
    var interaction: (string, string)
    if requestline[0] != "CONNECT" and proto == "http":
        incrementCounter("HTTP")
        requestline[1] = route
        headers["requestline"] = join(requestline, " ") 
        var req = proxyHeaders(headers) & req.body
        interaction = await mitmHttp(client, host, port, req, cid)
    else:
        incrementCounter("HTTPS")
        interaction = await mitmHttps(client, host, port, cid)

    incrementCounter("INTERACTIONS")
    #incrementCounter("INTERACTION_BYTES", len(interaction[0], ",", len(interaction[1])), StatType.bytes)

    #if SAVE_INTERACTION:
    #    if not saveInteraction(host, port, cid, parseRequest(interaction, cid)):
    #        echo "ERR while writing interaction to filesystem."


# ------ procs for watchout --------

#proc onFound(file: watchout.File) =
#    discard

#proc onChange(file: watchout.File) =
#    echo "Loading EasyList data"
#    BLOCKED_DOMAINS = getBlockedDomains()
    
#proc onDelete(file: watchout.File) =
#    discard
# ----------------------------------

proc startMITMProxy*(address: string, port: int) {.async.} = 
    ## Wrapper proc to start the MITMProxy.
    ## Will listen and process clients until stopped on the provided address:port.

    # Read Easylist domains
    BLOCKED_DOMAINS = getBlockedDomains()
    # Check for changes on file
    #newWatchout("customlist.txt", onChange, onFound, onDelete).start()

    # start server
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), address)

    try:
        server.listen()
        echo "[SERVER STARTED OK]"
        var client = newAsyncSocket(buffered=false)
        while true:
            client = await server.accept()
            let oid = $genOid()
            SOCKET_MAP[oid] = client
            incrementCounter("SERVER_ACCEPT")
            asyncCheck processClient(client, oid)

            #discard listCounters()
    except:
       echo "[start] " & getCurrentExceptionMsg()
       echo getStackTrace()
    finally:
        server.close()