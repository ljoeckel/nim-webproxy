import re, strutils, sequtils, tables, uri

type
  FilterType = enum
    DomainBlock, ElementHide, Exception, RegexBlock
  
  FilterRule = object
    ruleType: FilterType
    pattern: string
    options: seq[string]
  
  AdBlocker = object
    rules: seq[FilterRule]

# Helper: Check if a URL matches a domain-blocking rule (||example.com^)
proc isDomainBlocked(url: string, rule: FilterRule): bool =
  if rule.ruleType != DomainBlock: return false
  let domainPattern = rule.pattern.replace("||", r"^https?://([a-z0-9-]+\.)?")
  return url.match(re(domainPattern & r"($|\/)"))



# Helper: Check if a CSS selector matches an element-hiding rule (##.ad-banner)
proc isElementHidden(element: string, rule: FilterRule): bool =
  if rule.ruleType != ElementHide: return false
  return element.contains(rule.pattern.replace("##", ""))

# Parse a rule string into a `FilterRule`
proc parseRule(ruleStr: string): FilterRule =
  if ruleStr.startsWith("||") and ruleStr.endsWith("^"):
    FilterRule(ruleType: DomainBlock, pattern: ruleStr)
  elif ruleStr.startsWith("##"):
    FilterRule(ruleType: ElementHide, pattern: ruleStr)
  elif ruleStr.startsWith("@@"):
    FilterRule(ruleType: Exception, pattern: ruleStr.substr(2))
  elif '/' in ruleStr and ('/' in join(ruleStr.split('/')[1..^1], "") or ruleStr.endsWith('/')):
    FilterRule(ruleType: RegexBlock, pattern: ruleStr)
  else:
    raise newException(ValueError, "Unsupported rule: " & ruleStr)


# Simulate blocking a URL
proc shouldBlockUrl(blocker: AdBlocker, url: string): bool =
  for rule in blocker.rules:
    case rule.ruleType:
    of DomainBlock:
      if isDomainBlocked(url, rule): return true
    of RegexBlock:
      if url.match(re(rule.pattern)): return true
    else: discard
  return false

# Simulate hiding an HTML element
proc shouldHideElement(blocker: AdBlocker, element: string): bool =
  for rule in blocker.rules:
    if rule.ruleType == ElementHide and isElementHidden(element, rule):
      return true
  return false

# Example usage
let blocker = AdBlocker(rules: @[
  parseRule("||ads.example.com^"),            # Block domain
  parseRule("##.ad-banner"),                  # Hide element
  parseRule("@@||whitelist.example.com^"),    # Exception
  parseRule("/advert[0-9]*.png/")             # Regex block
])

let testUrl = "http://ads.example.com/popup.js"

let testElement = "<div class='ad-banner'>Ad</div>"

echo "Block URL? ", blocker.shouldBlockUrl(testUrl)           # true
echo "Hide Element? ", blocker.shouldHideElement(testElement)  # true