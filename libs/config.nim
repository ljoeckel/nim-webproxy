import std/[strutils, parsecfg]

type
    Configuration* = object 
        host*: string
        port*: int
        buffer_size*: int
        block_ads*: bool
        save_interaction*: bool
        save_raw_request*: bool
        list_statistics*: bool


proc getConfig*(): Configuration  =
    let dict = loadConfig("config.ini")
    var config = Configuration()

    config.host = dict.getSectionValue("proxy","host", "0.0.0.0")
    config.port = parseInt(dict.getSectionValue("proxy","port", "8081"))
    config.buffer_size = parseInt(dict.getSectionValue("proxy","buffer-size", "2048"))
    config.block_ads = parseBool(dict.getSectionValue("proxy","block-ads", "true"))
    config.save_interaction = parseBool(dict.getSectionValue("proxy","save-interaction", "true"))
    config.save_raw_request = parseBool(dict.getSectionValue("proxy","save-raw-request", "true"))
    config.list_statistics = parseBool(dict.getSectionValue("proxy","list-statistics", "true"))
    echo repr(config)
    return config
