import std/[algorithm, envvars, sequtils, asyncnet, asyncdispatch, nativesockets,
            strutils, net, tables, sets, oids, math, streams]
import system, parser, reader, certman, utils
import easylist
#import watchout
import statcounter
import decode
import config

const 
    BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
    OK = "HTTP/1.1 200 OK\r\n\r\n"
    NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
    NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"

var
    CONFIG: Configuration
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


proc sendRawRequest(target: AsyncSocket, req: string): Future[tuple[headers: string, body: string]] {.async.} =
    ## This proc sends the given raw HTML request (req) through the given socket (target).
    ## Returns a future tuple containing the headers an body of the response.
    incrementCounter("RAW_REQUEST")
    await target.send(req)
    if req.startsWith("HEAD") or req.startsWith("TRACE"):
        result = await target.readHTTPRequest(body=false)
    else:
        result = await target.readHTTPRequest()


proc tunnel(src: AsyncSocket, dst: AsyncSocket, cid: string): Future[string] {.async.} =    
    var buf = newStringStream()
    
    defer: 
        buf.close()
        incrementCounter("TUNNEL", len(result), StatType.bytes )

    proc srcHasData(): Future[string] {.async.}  =
        try:
            while not src.isClosed and not dst.isClosed:
                let data = src.recv(CONFIG.buffer_size)
                let future = await withTimeout(data, 2000)
                if future and not dst.isClosed and data.read.len() != 0:
                    let s = data.read()
                    #await dst.send(removeEncoding(s))
                    await dst.send(s)
                    buf.write(s)
                    incrementCounter("TUNNEL_SRC", len(s), StatType.bytes )
                else:
                    break
        except:
            incrementCounter("SRC_HAS_DATA ERR")
            echo "ERR! src.hasData ", getCurrentExceptionMsg()


    proc dstHasData(): Future[string] {.async.} =
        try:
            while not dst.isClosed and not src.isClosed:
                let data = dst.recv(CONFIG.buffer_size)
                let future = await withTimeout(data, 2000)
                if future and not src.isClosed and data.read.len() != 0:
                    let s = data.read()
                    await src.send(s)
                    buf.write(s)
                    incrementCounter("TUNNEL_DST", len(s), StatType.bytes )
                else:
                    break
        except:
            incrementCounter("DST_HAS_DATA ERR")
            echo "ERR! dstHasData", getCurrentExceptionMsg()

    await srcHasData() and dstHasData()
    buf.setPosition(0)
    result = buf.readAll()


proc mitmHttp(client: AsyncSocket, host: string, port: int, req: string, cid: string): Future[string] {.async.} = 
    let remote = newAsyncSocket(buffered=false)
    REMOTE_SOCKET_MAP[cid] = remote

    defer:
        removeSocket(cid)
        incrementCounter("HTTP")

    try:
        await remote.connect(host, Port(port))
        var res_info = await remote.sendRawRequest(removeEncoding(req))
        #var res_info = await remote.sendRawRequest(req)
        await client.send(res_info.headers & res_info.body)
        return req & "\r\n" & res_info.headers & res_info.body
    except:
        incrementCounter("HTTP_RESOLVE_HOST")
        echo "http Could not resolve remote host " & host
        await client.send(NOT_FOUND)


proc mitmHttps(client: AsyncSocket, host: string, port: int, cid: string): Future[string] {.async.} =
    defer:
        removeSocket(cid)
        incrementCounter("HTTPS")

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
        incrementCounter("CLIENT_SEND_OK_ERR")
        echo "Error 'client.send(OK)' cid=", cid
        return

    let ctx = getMITMContext(host)
    defer: 
        ctx.destroyContext()

    wrapConnectedSocket(ctx, client, handshakeAsServer, hostname = host)

    try:
        result = await tunnel(client, remote, cid)
    except:
        incrementCounter("TUNNEL_ERR")
        echo "Error tunnel cid=", cid


proc processClient(client: AsyncSocket, cid: string) {.async.} =
    defer:
        removeSocket(cid)

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

    if CONFIG.block_ads:
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
    
    var interaction: string
    if requestline[0] != "CONNECT" and proto == "http":
        requestline[1] = route
        headers["requestline"] = join(requestline, " ") 
        var req = proxyHeaders(headers) & req.body
        interaction = await mitmHttp(client, host, port, req, cid)
    else:
        interaction = await mitmHttps(client, host, port, cid)

    if CONFIG.save_interaction:
        processRequest(CONFIG, interaction, cid, host, port)


# ------ procs for watchout --------

#proc onFound(file: watchout.File) =
#    discard

#proc onChange(file: watchout.File) =
#    echo "Loading EasyList data"
#    BLOCKED_DOMAINS = getBlockedDomains()
    
#proc onDelete(file: watchout.File) =
#    discard
# ----------------------------------

proc startMITMProxy*(cfg: Configuration, address: string, port: int) {.async.} = 
    CONFIG = cfg # update global CONFIG var
    ## Wrapper proc to start the MITMProxy.
    ## Will listen and process clients until stopped on the provided address:port.

    # Read Easylist domains
    if CONFIG.block_ads:
        BLOCKED_DOMAINS = getBlockedDomains()
        # Check for changes on file
        #newWatchout("customlist.txt", onChange, onFound, onDelete).start()

    # start server
    let server = newAsyncSocket(buffered=false)
    defer:
        server.close()

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

            if CONFIG.list_statistics:
                discard listCounters()
    except:
       echo "[start] " & getCurrentExceptionMsg()
       echo getStackTrace()