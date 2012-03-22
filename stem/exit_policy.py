import re

class ExitPolicyIterator:
  """
  Basic iterator for cycling through ExitPolicy entries.
  """
  
  def __init__(self, head):
    self.head = head
  
  def next(self):
    if self.head:
      lastHead = self.head
      self.head = self.head.nextRule
      return lastHead
    else: raise StopIteration

class ExitPolicy:
  """
  Single rule from the user's exit policy. These are chained together to form
  complete policies.
  """
  
  def __init__(self, ruleEntry, nextRule):
    """
    Exit policy rule constructor.
    
    Arguments:
      ruleEntry - tor exit policy rule (for instance, "reject *:135-139")
      nextRule  - next rule to be checked when queries don't match this policy
    """
    
    # cached summary string
    self.summaryStr = None
    
    # sanitize the input a bit, cleaning up tabs and stripping quotes
    ruleEntry = ruleEntry.replace("\\t", " ").replace("\"", "")
    
    self.ruleEntry = ruleEntry
    self.nextRule = nextRule
    self.isAccept = ruleEntry.startswith("accept")
    
    # strips off "accept " or "reject " and extra spaces
    ruleEntry = ruleEntry[7:].replace(" ", "")
    
    # split ip address (with mask if provided) and port
    if ":" in ruleEntry: entryIp, entryPort = ruleEntry.split(":", 1)
    else: entryIp, entryPort = ruleEntry, "*"
    
    # sets the ip address component
    self.isIpWildcard = entryIp == "*" or entryIp.endswith("/0")
    
    # checks for the private alias (which expands this to a chain of entries)
    if entryIp.lower() == "private":
      entryIp = PRIVATE_IP_RANGES[0]
      
      # constructs the chain backwards (last first)
      lastHop = self.nextRule
      prefix = "accept " if self.isAccept else "reject "
      suffix = ":" + entryPort
      for addr in PRIVATE_IP_RANGES[-1:0:-1]:
        lastHop = ExitPolicy(prefix + addr + suffix, lastHop)
      
      self.nextRule = lastHop # our next hop is the start of the chain
    
    if "/" in entryIp:
      ipComp = entryIp.split("/", 1)
      self.ipAddress = ipComp[0]
      self.ipMask = int(ipComp[1])
    else:
      self.ipAddress = entryIp
      self.ipMask = 32
    
    # constructs the binary address just in case of comparison with a mask
    if self.ipAddress != "*":
      self.ipAddressBin = ""
      for octet in self.ipAddress.split("."):
        # Converts the int to a binary string, padded with zeros. Source:
        # http://www.daniweb.com/code/snippet216539.html
        self.ipAddressBin += "".join([str((int(octet) >> y) & 1) for y in range(7, -1, -1)])
    else:
      self.ipAddressBin = "0" * 32
    
    # sets the port component
    self.minPort, self.maxPort = 0, 0
    self.isPortWildcard = entryPort == "*"
    
    if entryPort != "*":
      if "-" in entryPort:
        portComp = entryPort.split("-", 1)
        self.minPort = int(portComp[0])
        self.maxPort = int(portComp[1])
      else:
        self.minPort = int(entryPort)
        self.maxPort = int(entryPort)
    
    # if both the address and port are wildcards then we're effectively the
    # last entry so cut off the remaining chain
    if self.isIpWildcard and self.isPortWildcard:
      self.nextRule = None
  
  def isExitingAllowed(self):
    """
    Provides true if the policy allows exiting whatsoever, false otherwise.
    """
    
    if self.isAccept: return True
    elif self.isIpWildcard and self.isPortWildcard: return False
    elif not self.nextRule: return False # fell off policy (shouldn't happen)
    else: return self.nextRule.isExitingAllowed()
  
  def check(self, ipAddress, port):
    """
    Checks if the rule chain allows exiting to this address, returning true if
    so and false otherwise.
    """
    
    port = int(port)
    
    # does the port check first since comparing ip masks is more work
    isPortMatch = self.isPortWildcard or (port >= self.minPort and port <= self.maxPort)
    
    if isPortMatch:
      isIpMatch = self.isIpWildcard or self.ipAddress == ipAddress
      
      # expands the check to include the mask if it has one
      if not isIpMatch and self.ipMask != 32:
        inputAddressBin = ""
        for octet in ipAddress.split("."):
          inputAddressBin += "".join([str((int(octet) >> y) & 1) for y in range(7, -1, -1)])
        
        isIpMatch = self.ipAddressBin[:self.ipMask] == inputAddressBin[:self.ipMask]
      
      if isIpMatch: return self.isAccept
    
    # our policy doesn't concern this address, move on to the next one
    if self.nextRule: return self.nextRule.check(ipAddress, port)
    else: return True # fell off the chain without a conclusion (shouldn't happen...)
  
  def getSummary(self):
    """
    Provides a summary description of the policy chain similar to the
    consensus. This excludes entries that don't cover all ips, and is either
    a whitelist or blacklist policy based on the final entry. For instance...
    accept 80, 443        # just accepts ports 80/443
    reject 1-1024, 5555   # just accepts non-privilaged ports, excluding 5555
    """
    
    if not self.summaryStr:
      # determines if we're a whitelist or blacklist
      isWhitelist = False # default in case we don't have a catch-all policy at the end
      
      for rule in self:
        if rule.isIpWildcard and rule.isPortWildcard:
          isWhitelist = not rule.isAccept
          break
      
      # Iterates over the rules and adds the the ports we'll return (ie, allows
      # if a whitelist and rejects if a blacklist). Reguardless of a port's
      # allow/reject policy, all further entries with that port are ignored since
      # policies respect the first matching rule.
      
      displayPorts, skipPorts = [], []
      
      for rule in self:
        if not rule.isIpWildcard: continue
        
        if rule.minPort == rule.maxPort:
          portRange = [rule.minPort]
        else:
          portRange = range(rule.minPort, rule.maxPort + 1)
        
        for port in portRange:
          if port in skipPorts: continue
          
          # if accept + whitelist or reject + blacklist then add
          if rule.isAccept == isWhitelist:
            displayPorts.append(port)
          
          # all further entries with this port are to be ignored
          skipPorts.append(port)
      
      # gets a list of the port ranges
      if displayPorts:
        displayRanges, tmpRange = [], []
        displayPorts.sort()
        displayPorts.append(None) # ending item to include last range in loop
        
        for port in displayPorts:
          if not tmpRange or tmpRange[-1] + 1 == port:
            tmpRange.append(port)
          else:
            if len(tmpRange) > 1:
              displayRanges.append("%i-%i" % (tmpRange[0], tmpRange[-1]))
            else:
              displayRanges.append(str(tmpRange[0]))
            
            tmpRange = [port]
      else:
        # everything for the inverse
        isWhitelist = not isWhitelist
        displayRanges = ["1-65535"]
      
      # constructs the summary string
      labelPrefix = "accept " if isWhitelist else "reject "
      
      self.summaryStr = (labelPrefix + ", ".join(displayRanges)).strip()
    
    return self.summaryStr
  
  def __iter__(self):
    return ExitPolicyIterator(self)
  
  def __str__(self):
    # This provides the actual policy rather than the entry used to construct
    # it so the 'private' keyword is expanded.
    
    acceptanceLabel = "accept" if self.isAccept else "reject"
    
    if self.isIpWildcard:
      ipLabel = "*"
    elif self.ipMask != 32:
      ipLabel = "%s/%i" % (self.ipAddress, self.ipMask)
    else: ipLabel = self.ipAddress
    
    if self.isPortWildcard:
      portLabel = "*"
    elif self.minPort != self.maxPort:
      portLabel = "%i-%i" % (self.minPort, self.maxPort)
    else: portLabel = str(self.minPort)
    
    myPolicy = "%s %s:%s" % (acceptanceLabel, ipLabel, portLabel)
    
    if self.nextRule:
      return myPolicy + ", " + str(self.nextRule)
    else: return myPolicy

