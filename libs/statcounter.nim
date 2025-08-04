import std/[algorithm, assertions, math, sequtils, strutils, strformat, tables]

const 
    GB  = 1024*1024*1024
    MB = 1024*1024
    KB = 1024

type
    StatType* = enum
        events,
        bytes

    StatCounter = object
        key: string
        value: int
        typ: StatType

var
    COUNTERS = initTable[string, StatCounter]()

proc newStatCounter(key: string, value: int = 0, typ: StatType = StatType.events): StatCounter =
    result = StatCounter(key: key, value: value, typ: typ)

proc `$`(c: StatCounter): string =
    result = c.key & ": "
    let b = c.value
    var s: string
    if c.typ == StatType.bytes:
        if b > GB: 
            s = strip(fmt"{(b/GB):<9.3f}") & " gb"
        elif b > MB: 
            s = strip(fmt"{(b/MB):<9.3f}") & " mb"
        elif b > KB: 
            s =  strip(fmt"{(b/KB):<9.3f}") & " kb"
        else: 
            s = $b & " b"
    else:
        s = $b
    result = c.key & ": " & s

proc getCounter(key: string): StatCounter =
    return COUNTERS.getOrDefault(key, newStatCounter(key))

proc listCounters*(): string =
    if COUNTERS.len == 0:
        return ""

    let sortedKeys = sorted(COUNTERS.keys.toSeq)
    for idx, key in sortedKeys:
        stdout.write(getCounter(key))
        if idx+1 < len(sortedKeys):
            stdout.write(", ")
        else:
            stdout.writeLine("")

proc incrementCounter*(key: string, increment: int = 1, typ: StatType = StatType.events) =
    var cnt = COUNTERS.getOrDefault(key, newStatCounter(key, 0, typ))
    cnt.value += increment
    COUNTERS[key] = cnt

proc setCounter*(key: string, value: int, typ: StatType = StatType.events) =
    var cnt = COUNTERS.getOrDefault(key, newStatCounter(key, value, typ))
    cnt.value = value
    COUNTERS[key] = cnt