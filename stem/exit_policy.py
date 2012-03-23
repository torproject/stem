"""
Tor Exit Policy information and requirements for its features. These can be
easily parsed and compared, for instance...

>>> exit_policies = stem.exit_policy.ExitPolicy()
>>> exit_policies.add("reject *:*")
>>> print exit_policies
reject *:*

ExitPolicyLine - Single rule from the exit policy
  |- __str__ - string representation
  +- check   - check if exiting to this ip is allowed

ExitPolicy - List of ExitPolicyLine objects
  |- __str__  - string representation
  |- __iter__ - ExitPolicyLine entries for the exit policy
  |- check    - check if exiting to this ip is allowed
  |- add      - add new rule to the exit policy
  +- isExitingAllowed - check if exit node
"""

# ip address ranges substituted by the 'private' keyword
PRIVATE_IP_RANGES = ("0.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12")

class ExitPolicyLine:
  """
  Single rule from the user's exit policy. These are chained together to form
  complete policies.
  """

  def __init__(self, rule_entry):
    """
    Exit Policy line constructor.
    """
    # sanitize the input a bit, cleaning up tabs and stripping quotes
    rule_entry = rule_entry.replace("\\t", " ").replace("\"", "")
    
    self.rule_entry = rule_entry
    self.is_accept = rule_entry.startswith("accept")
    
    # strips off "accept " or "reject " and extra spaces
    rule_entry = rule_entry[7:].replace(" ", "")
    
    # split ip address (with mask if provided) and port
    if ":" in rule_entry: entry_ip, entry_port = rule_entry.split(":", 1)
    else: entry_ip, entry_port = rule_entry, "*"
    
    # sets the ip address component
    self.is_ip_wildcard = entry_ip == "*" or entry_ip.endswith("/0")
    
    # separate host and mask
    if "/" in entry_ip:
      ip_comp = entry_ip.split("/", 1)
      self.ip_address = ip_comp[0]
      self.ip_mask = int(ip_comp[1])
    else:
      self.ip_address = entry_ip
      self.ip_mask = 32
    
    # constructs the binary address just in case of comparison with a mask
    if self.ip_address != "*":
      self.ip_address_bin = ""
      for octet in self.ip_address.split("."):
        # Converts the int to a binary string, padded with zeros. Source:
        # http://www.daniweb.com/code/snippet216539.html
        self.ip_address_bin += "".join([str((int(octet) >> y) & 1) for y in range(7, -1, -1)])
    else:
      self.ip_address_bin = "0" * 32
      
    # sets the port component
    self.min_port, self.max_port = 0, 0
    self.is_port_wildcard = entry_port == "*"
    
    if entry_port != "*":
      if "-" in entry_port:
        port_comp = entry_port.split("-", 1)
        self.min_port = int(port_comp[0])
        self.max_port = int(port_comp[1])
      else:
        self.min_port = int(entry_port)
        self.max_port = int(entry_port)
        
  def __str__(self):
    # This provides the actual policy rather than the entry used to construct
    # it so the 'private' keyword is expanded.
        
    acceptance_label = "accept" if self.is_accept else "reject"
        
    if self.is_ip_wildcard:
      ip_label = "*"
    elif self.ip_mask != 32:
      ip_label = "%s/%i" % (self.ip_address, self.ip_mask)
    else: ip_label = self.ip_address
        
    if self.is_port_wildcard:
      port_label = "*"
    elif self.min_port != self.max_port:
      port_label = "%i-%i" % (self.min_port, self.max_port)
    else: port_label = str(self.min_port)
        
    my_policy = "%s %s:%s" % (acceptance_label, ip_label, port_label)
    return my_policy
    
  def check(self, ip_address, port):
    """
    Checks if the rule chain allows exiting to this address, returning true if
    so and false otherwise.
    """
      
    port = int(port)
    
    # does the port check first since comparing ip masks is more work
    is_port_match = self.is_port_wildcard or (port >= self.min_port and port <= self.max_port)
    
    if is_port_match:
      is_ip_match = self.is_ip_wildcard or self.ip_address == ip_address
        
       # expands the check to include the mask if it has one
      if not is_ip_match and self.ip_mask != 32:
        input_address_bin = ""
        for octet in ip_address.split("."):
          input_address_bin += "".join([str((int(octet) >> y) & 1) for y in range(7, -1, -1)])

        is_ip_match = self.ip_address_bin[:self.ip_mask] == input_address_bin[:self.ip_mask]
                
      if is_ip_match: return self.is_accept
            
    # fell off the chain without a conclusion (shouldn't happen...)
    return False
      
    
class ExitPolicy:
  """
  Provides a wrapper to ExitPolicyLine. This is iterable and can be stringified for
  individual Exit Policy lines.
  """
    
  def __init__(self):
    """
    ExitPolicy constructor
    """
    self._policies = []

  def add(self, rule_entry):
    """
    This method is used to add an Exit Policy rule to the list of policies.
        
    Arguments:
    rule_entry (str) - exit policy rule in the format "accept|reject ADDR[/MASK][:PORT]"
                       ex - "accept 18.7.22.69:*"
    """
        # checks for the private alias (which expands this to a chain of entries)
    if "private" in rule_entry.lower():
      for addr in PRIVATE_IP_RANGES:
        new_entry = rule_entry.replace("private", addr)
        self._policies.append(ExitPolicyLine(new_entry))
    else:
      self._policies.append(ExitPolicyLine(rule_entry))
    
  def is_exiting_allowed(self):
    """
    Provides true if the policy allows exiting whatsoever, false otherwise.
    """
    for policy in self._policies:
      if policy.is_accept: return True
      elif policy.is_ip_wildcard and policy.is_port_wildcard: return False
    
  def check(self, ip_address, port):
    """
    Checks if the rule chain allows exiting to this address, returning true if
    so and false otherwise.
    """
    
    for policy in self._policies:
      if policy.check(ip_address, port): return True
        
      return False
    
  def __iter__(self):
    """
    Provides an ordered listing of policies in this Exit Policy
    """
    for policy in self._policies:
      yield policy
    
  def __str__(self):
    """
    Provides the string used to construct the Exit Policy      
    """
    return ' , '.join([str(policy) for policy in self._policies])
  
