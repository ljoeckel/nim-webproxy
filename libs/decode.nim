import std/[tables, logging, strformat, os, times, strutils]
import parser 
import zippy
import brotli
import config

const RNRN = "\r\n\r\n"
const IMAGES_D = "interactions"
var IMAGE_COUNTER = 0

proc saveImage(content_type: string, cid: string, host: string, port: int, data: string): bool =
    if data.isEmptyOrWhitespace:
        return false

    var media = content_type
    if content_type.contains(";"):
        media = content_type.split(";")[0] # text/html; charset=UTF-8 -> text/html
    let s = media.split("/") # text/html
    let content_type = s[0] # text
    let extension = s[1] # html

    let dirname = joinPath(IMAGES_D, fmt"{host}-{port}/{content_type}")
    if not dirExists(dirname): createDir(dirname)
    let dt = now()
    let timestamp = dt.format("yyyy-MM-dd-HH:mm:ss")
    let fn = joinPath(dirname, fmt"{cid}-{timestamp}-{IMAGE_COUNTER}.{extension}")
    try:
        var f = open(fn, fmWrite)
        defer:
            f.close()
        f.write(data)
        inc(IMAGE_COUNTER)
        log(lvlInfo, fmt"[saveImage] {data.len} written to {fn}")
    except: 
        log(lvlError, fmt"[saveImage] path:{fn} cid: {cid} Exception: {getCurrentExceptionMsg()}")
        return false
    
    return true


proc processRequest*(config: Configuration, request: var string, cid: string, host: string, port: int) =
    if config.save_raw_request:
        discard saveImage("request/request", cid, host, port, request)
    
    var index: int
    while index < len(request) and index != -1:
        var headers: Table[string, string]
        #var header = ""
        var body = RNRN
        let start_index = index
        index = request.find(RNRN, start=start_index)
        if index != -1:
            index += 4  # exclude \r\n\r\n
            headers = parseHeaders(request[start_index .. index - 1])
            #let header = proxyHeaders(headers)
            let contentLength = parseInt(headers.getOrDefault("content-length","0"))
            if contentLength + index - 1 > request.len:
                log(lvlError, fmt"[processRequest] Could not extract body. Invalid | Missing Body data: contentLength:{contentLength} index+CL-1:{index+contentLength-1} request.len:{request.len}")
                break

            if contentLength > 0:
                body = request[index .. index + contentLength - 1]
                inc(index, contentLength)

                var content_type = headers.getOrDefault("content-type", "")
                if not content_type.isEmptyOrWhitespace:
                    let encoding = headers.getOrDefault("content-encoding", "")
                    if not encoding.isEmptyOrWhitespace:
                        if encoding == "br":  # brotli
                            try: 
                                body = decompressBrotli(body)
                            except:
                                log(lvlError, fmt"[processRequest] decompressBrotli exception:{getCurrentExceptionMsg()}")
                        else:
                            try:
                                body = uncompress(body)
                            except:
                                log(lvlError, fmt"[processRequest] zippy exception:{getCurrentExceptionMsg()}")

                    discard saveImage(content_type, cid, host, port, body)