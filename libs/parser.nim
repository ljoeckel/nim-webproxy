import std/[uri, re, tables, strutils]

let HEADER_REGEX = re"^([A-Za-z0-9-]*):(.*)$"
let REQUESTLINE_REGEX = re"([A-Z]{1,511}) ([^ \n\t]*) HTTP\/[0-9]\.[0-9]"
let RESPONSELINE_REGEX = re"HTTP/[0-9]\.[0-9] [0-9]{3} [A-Z ]*"
let RESPONSECODE_REGEX = re"([0-9]{3})"
let PROXY_HOST_REGEX = re"(http:\/\/|https:\/\/)?([^/<>:""'\|?*]*):?([0-9]{1,5})?(\/[^\n\t]*)?"
let CONTENT_TYPE = re"Content-Type: ([^\r\n]*\r\n)"
let ACCEPT_ENCODING = re"Accept-Encoding: ([^\r\n]*)\r\n"
let TRANSFER_ENCODING = re"Transfer-Encoding: ([^\r\n]*)\r\n"
let CONTENT_LENGTH = re"Content-Length: ([^\r\n]*)\r\n"
let HTTP_PROTO = "http"
let HTTPS_PROTO = "https"
let PROXY_HEADERS = ["Proxy-Connection", "requestline", "responseline"]
let ALLOWED_DATA_TYPES = ["text", "application", "multipart", "model", "message"]


proc parseHeaders*(headers: string): Table[string, string] =
    ## Maps a raw header section to a Table.
    ## Inserts the requestline and responseline headers.
    ## Returns the populated table.
    for header in headers.splitLines():
        var matches: array[2, string]
        if re.find(header, HEADER_REGEX, matches) != -1:
            result[matches[0].strip()] = matches[1].strip()
        elif re.find(header, REQUESTLINE_REGEX, matches) != -1:
            result["requestline"] = header 
        elif re.find(header, RESPONSELINE_REGEX, matches) != -1:
            result["responseline"] = header


proc parseProxyHost*(host: string): tuple[proto: string, host: string,
                                          port: int, route: string] = 
    ## Parse the host that we are asked to proxy to.
    ## Returns a tuple representing each part of the host provided.
    var matches: array[4, string]
    if re.find(host, PROXY_HOST_REGEX, matches) != -1:
        let host = matches[1]
        let proto = 
            if matches[0] == "" or matches[2] == "443": HTTPS_PROTO 
            else: HTTP_PROTO
        let route = 
            if matches[3] == "": "/" 
            else: matches[3]
        let port = 
            if matches[2] == "" and proto == HTTPS_PROTO: 443
            elif matches[2] == "" and proto == HTTP_PROTO: 80
            else: parseInt(matches[2])
        result = (proto: proto, host: host, port: port, route: route)
    else:
        result = (proto: "", host: "", port: 80, route: "")


proc proxyHeaders*(headers: Table[string, string]): string =
    ## Create the header section for a raw request by using the provided table, 
    ## returns string.
    ## Will remove headers pertaining to the proxy, such headers are contained in PROXY_HEADERS.
    if headers.hasKey("requestline"):
        result = join([headers["requestline"], result], "\r\n")
    elif headers.hasKey("responseline"):
        result = join([headers["responseline"], result], "\r\n")
    for k, v in headers.pairs:
        if not PROXY_HEADERS.contains(k) :
            result = result & join([k, v], ": ") & "\r\n"
    result = result & "\r\n"


proc parseRequest*(request: string, cid: string): seq[tuple[headers: string, body: string]] =
    echo "cid:", cid, " request:", request
    ## Attempts to parse an HTTP stream correctly.
    ## Very scuffed.
    ## Should refactor + relocate most of this code.
    #let baseLog = fmt"[{cid}][parseRequest]"
    var requests: seq[tuple[headers: string, body: string]]
    #log(lvlDebug, baseLog & fmt"[REQ_LENGTH][{$request.high()}]")

    # Iterate over the string and parse request/responses while doing so.
    # I should use a StringStream for this.
    var index: int
    while index < len(request) and index != -1:
        var rid = len(requests) + 1
        var headers: Table[string, string]
        var body = "\r\n\r\n"
        let start_index = index
        index = request.find("\r\n\r\n", start=start_index)
        if index != -1:
            # the -1's are to adjust for 0 notation of sequences.
            # exclude \r\n\r\n
            index += 4
            headers = parseHeaders(request[start_index .. index - 1])
            #if not (headers.hasKey("requestline") or headers.hasKey("responseline")):
            #        log(lvlError, 
            #            baseLog & fmt"[{rid}][EMPTY HEADERS !]")
            if headers.hasKey("Content-Length"):
                let contentLength = parseInt(headers["Content-Length"].strip())
                body = request[index .. index + contentLength - 1]
                index = index + contentLength 
        let interaction = (headers: proxyHeaders(headers), body: body)
        requests.add(interaction)
    return requests


#proc removeEncoding*(req: string): string =
    ## This completely removes any Transfer-Encoding headers from the given request
#    return req.replace(re"Transfer-Encoding: .*\r\n", "")


proc decode() =
    ## proc to decode the data from the appropriate transfer-encoding
    ## -- wip
    # elif headers.hasKey("transfer-encoding") or headers.hasKey("Transfer-Encoding"):
    #     log(lvlDebug, 
    #         baseLog & fmt"[{rid}][CHUNKED ENCODING]")
    #     ## Since i remove the Accept-Encoding header, this should only be chunked.
    #     ## But I will add validation.
    #     ## Read the chunks and populate the body.
    #     var chunks: seq[string]
    #     while true:
    #         var chunk_start = request.find("\r\n", start=index)
    #         if chunk_start == -1:
    #             break

    #         log(lvlDebug, 
    #             baseLog & fmt"[{rid}][CHUNK_START][{chunk_start}]")
    #         var hex_chunk_size = request[index .. chunk_start - 1]

    #         var chunk_size: int
    #         try:
    #             chunk_size = fromHex[int](hex_chunk_size)
    #         except:
    #             chunk_size = 0

    #         ## +2 to skip the \r\n after the chunk length
    #         ## -1 for 0 notation
    #         chunks.add(request[chunk_start + 2 .. chunk_start + 2 + chunk_size - 1])
    #         log(lvlDebug, 
    #             baseLog & fmt"[{rid}][CHUNKED][{chunk_size}]")

    #         ## +4 to skip \r\n twice
    #         index = chunk_start + chunk_size + 4
    #         if chunk_size == 0:
    #             break

    #     body = join(chunks, "")


proc excludeData*(req: string): bool = 
    ## My Half-assed attempt at filtering out data.
    ## Since the sockets seem to be reused for multiple request, It's making it hard.
    ## Disable content-type checking for now, using content-length only.
    var content_length = @[""]
    if find(req, CONTENT_LENGTH, content_length) != -1:
        #log(lvlDebug, "Content-Length: " & content_length)
        if parseInt(content_length[0]) > 1000000:
            #log(lvlDebug, "EXCLUDED: Content-Length: " & content_length)
            return true
    else:
        return false

proc getUri*(request: string): Uri =
    parseUri(request)

# -------------------------------------------------------------
# Host=push.services.mozilla.com
# Origin=wss://push.services.mozilla.com/
# Sec-Fetch-Site=cross-site
# Sec-WebSocket-Version=13
# Accept-Encoding=gzip, deflate, br, zstd
# User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0
# Sec-Fetch-Mode=websocket
# Connection=keep-alive, Upgrade
# Sec-Fetch-Dest=empty
# Pragma=no-cache
# Sec-WebSocket-Protocol=push-notification
# Upgrade=websocket
# Accept=*/*
# Cache-Control=no-cache
# requestline=GET / HTTP/1.1
# Accept-Language=de,en-US;q=0.7,en;q=0.3
# Sec-WebSocket-Extensions=permessage-deflate
# Sec-WebSocket-Key=NNV4fbEv0a11Z3iqsVHhLQ==


# responseline=HTTP/1.1 200 OK
# X-Request-Id=081ef880-6e28-11f0-bdf3-6164c355040e
# Vary=Accept-Encoding
# Connection=keep-alive
# Content-Length=294395
# X-Memcached-Key=-----0-www.focus.de/-
# Last-Modified=Thu, 31 Jul 2025 16:04:26 GMT
# Expires=Thu, 31 Jul 2025 16:05:46 GMT
# Date=Thu, 31 Jul 2025 16:04:59 GMT
# Content-Type=text/html; charset=utf-8
# Cache-Control=public, max-age=47
# Permissions-Policy=ch-ua-model=*,ch-ua-platform-version=*
# Content-Encoding=gzip
# Accept-CH=sec-ch-ua-model,sec-ch-ua-platform-version


type 
    Header* = object 
        cid*: string
        accept*: string
        accept_encoding*: string
        accept_language*: string
        cache_control*: string
        connection*: string
        content_encoding*: string
        content_length*: int
        content_type*: string
        date*: string
        encoding*: string
        expires*: string
        host*: string
        last_modified*: string
        origin*: string
        pragma*: string
        responseline*: string
        response_status_code*: int
        requestline*: string
        user_agent*: string
        vary*: string

proc newHeader(contentType: string = ""): Header =
    return Header(contentType: contentType)

proc getHeader*(cid: string, s: string): Header =
    let headers = parseHeaders(s)

    var header = Header()
    header.cid = cid
    header.accept = headers.getOrDefault("Accept","")
    header.accept_encoding = headers.getOrDefault("Accept-Encoding","")
    header.accept_language = headers.getOrDefault("Accept-Language","")
    header.cache_control = headers.getOrDefault("Cache-Control","")
    header.connection = headers.getOrDefault("Connection","")
    header.content_encoding = headers.getOrDefault("Content-Encoding","")
    header.content_length = parseInt(headers.getOrDefault("Content-Length","0"))
    header.content_type = headers.getOrDefault("Content-Type","")
    header.date = headers.getOrDefault("Date","")
    header.encoding = headers.getOrDefault("Encoding","")
    header.expires = headers.getOrDefault("Expires","")
    header.host = headers.getOrDefault("Host","")
    header.last_modified = headers.getOrDefault("Last-Modified","")
    header.origin = headers.getOrDefault("Origin","")
    header.pragma = headers.getOrDefault("Pragma","")
    header.requestline = headers.getOrDefault("requestline","")

    header.responseline = headers.getOrDefault("responseline","")
    if not header.responseline.isEmptyOrWhitespace:
        var matches: array[1, string]
        if re.find(header.responseline, RESPONSECODE_REGEX, matches) != -1:
            header.response_status_code = parseInt(matches[0])

    header.user_agent = headers.getOrDefault("User-Agent","")
    header.vary = headers.getOrDefault("Vary","")

    return header

proc isSupportedContent(header: Header): bool =
    let ct = normalize(header.content_type)
    if header.content_type.contains("text/"):
        return true

proc hasContent*(header: Header): bool =
    result = false
    if header.content_length > 0 and isSupportedContent(header):
        result = true

proc getBody*(header: Header, request: string): string =
    if not header.content_length > 0:
        echo "ERROR: no content-length"
        return

    var index = request.find("\r\n\r\n", start=0)
    if index != -1:
        index += 4
        return request[index .. ^1]
    else:
        return ""
