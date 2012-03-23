# ip address ranges substituted by the 'private' keyword
PRIVATE_IP_RANGES = ("0.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12")

class ExitPolicyLine:
    def __init__(self, ruleEntry):
        # sanitize the input a bit, cleaning up tabs and stripping quotes
        ruleEntry = ruleEntry.replace("\\t", " ").replace("\"", "")

        self.ruleEntry = ruleEntry
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
            # constructs the chain backwards (last first)
            prefix = "accept " if self.isAccept else "reject "
            suffix = ":" + entryPort
            for addr in PRIVATE_IP_RANGES:
                # TODO: Add ExitPolicy.add method 
                ExitPolicy.add(prefix + addr + suffix) 

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
        return myPolicy
    
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
            
        # fell off the chain without a conclusion (shouldn't happen...)
        return False
      

class ExitPolicy:
    """
    Single rule from the user's exit policy. These are chained together to form
    complete policies.
    """
  
    def __init__(self):
        """
        Exit policy rule constructor.
        """
        self._policies = []
  
    def add(self, ruleEntry):
        self._policies.append(ExitPolicyLine(ruleEntry))

    def isExitingAllowed(self):
        """
        Provides true if the policy allows exiting whatsoever, false otherwise.
        """
        for policy in self._policies:
          if policy.isAccept: return True
          elif policy.isIpWildcard and self.isPortWildcard: return False

  
    def check(self, ipAddress, port):
        """
        Checks if the rule chain allows exiting to this address, returning true if
        so and false otherwise.
        """
    
        for policy in self._policies:
            if policy.check(ipAddress, port): return True

        return False
  
    def __iter__(self):
        for policy in self._policies:
            yield policy
  
    def __str__(self):
        # This provides the actual policy rather than the entry used to construct
        # it so the 'private' keyword is expanded.
      
        return ' , '.join([str(policy) for policy in self._policies])

