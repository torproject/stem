"""
Representation of tor exit policies. These can be easily used to check if
exiting to a destination is permissable or not. For instance...

::

  >>> exit_policies = stem.exit_policy.ExitPolicy()
  >>> exit_policies.add("accept *:80")
  >>> exit_policies.add("accept *:443")
  >>> exit_policies.add("reject *:*")
  >>> print exit_policies
  accept *:80 , accept *:443, reject *:*
  >>> print exit_policies.get_summary()
  accept 80, 443
  >>> exit_policies.check("www.google.com", 80)
  True
  
  >>> microdesc_exit_policy = stem.exit_policy.MicrodescriptorExitPolicy("accept 80,443")
  >>> print microdesc_exit_policy
  accept 80,443
  >>> microdesc_exit_policy.check("www.google.com", 80)
  True
  >>> microdesc_exit_policy.check(80)
  True

::

  ExitPolicyRule - Single rule of an exit policy
    |- is_address_wildcard - checks if we'll accept any address for our type
    |- is_port_wildcard - checks if we'll accept any port
    |- is_match - checks if we match a given destination
    +- __str__ - string representation for this rule

  ExitPolicy - List of ExitPolicyLine objects
    |- __str__  - string representation
    |- __iter__ - ExitPolicyLine entries for the exit policy
    |- check    - check if exiting to this ip is allowed
    |- add      - add new rule to the exit policy
    |- get_summary - provides a summary description of the policy chain
    +- is_exiting_allowed - check if exit node

  MicrodescriptorExitPolicy - Microdescriptor exit policy
    |- check - check if exiting to this port is allowed
    |- ports - returns a list of ports
    |- is_accept - check if it's a list of accepted/rejected ports
    +- __str__ - return the summary
"""

import stem.util.connection
import stem.util.enum

AddressType = stem.util.enum.Enum(("WILDCARD", "Wildcard"), ("IPv4", "IPv4"), ("IPv6", "IPv6"))

# ip address ranges substituted by the 'private' keyword
PRIVATE_IP_RANGES = ("0.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8",
                     "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12")

# TODO: The ExitPolicyRule's exitpatterns are used everywhere except the torrc.
# This is fine for now, but we should add a subclass to handle those slight
# differences later if we want to provide the ability to parse torrcs.

# TODO: The ExitPolicyRule could easily be a mutable class if we did the
# following...
#
# * Provided setter methods that acquired an RLock which also wrapped all of
#   our current methods to provide thread safety.
#
# * Reset our derived attributes (self._addr_bin, self._mask_bin, and
#   self._str_representation) when we changed something that it was based on.
#
# That said, I'm not sure if this is entirely desirable since for most use
# cases we *want* the caller to have an immutable ExitPolicy (since it
# reflects something they... well, can't modify). However, I can think of
# some use cases where we might want to construct custom policies. Mabye make
# it a CustomExitPolicyRule subclass?

class ExitPolicyRule(object):
  """
  Single rule from the user's exit policy. These rules are chained together to
  form complete policies that describe where a relay will and will not allow
  traffic to exit.
  
  The format of these rules are formally described in the dir-spec as an
  "exitpattern". Note that while these are similar to tor's man page entry for
  ExitPolicies, it's not the exact same. An exitpattern is better defined and
  scricter in what it'll accept. For instance, ports are not optional and it
  does not contain the 'private' alias.
  
  This should be treated as an immutable object.
  
  :var str rule: rule that we were originally created from
  :var bool is_accept: indicates if exiting is allowed or disallowed
  
  :var AddressType address_type: type of address that we have
  :var str address: address that this rule is for
  :var str mask: subnet mask for the address (ex. "255.255.255.0")
  :var int masked_bits: number of bits the subnet mask represents, None if the mask can't have a bit representation
  
  :var int min_port: lower end of the port range that we include (inclusive)
  :var int max_port: upper end of the port range that we include (inclusive)
  
  :param str rule: exit policy rule to be parsed
  
  :raises: ValueError if input isn't a valid tor exit policy rule
  """
  
  def __init__(self, rule):
    self.rule = rule
    
    # policy ::= "accept" exitpattern | "reject" exitpattern
    # exitpattern ::= addrspec ":" portspec
    
    if rule.startswith("accept"):
      self.is_accept = True
    elif rule.startswith("reject"):
      self.is_accept = False
    else:
      raise ValueError("An exit policy must start with either 'accept' or 'reject': %s" % rule)
    
    exitpattern = rule[6:]
    
    if not exitpattern.startswith(" ") or (len(exitpattern) - 1 != len(exitpattern.lstrip())) :
      raise ValueError("An exit policy should have a space separating its accept/reject from the exit pattern: %s" % rule)
    
    exitpattern = exitpattern[1:]
    
    if not ":" in exitpattern:
      raise ValueError("An exitpattern must be of the form 'addrspec:portspec': %s" % rule)
    
    self.address = None
    self.address_type = None
    self.mask = self.masked_bits = None
    self.min_port = self.max_port = None
    
    addrspec, portspec = exitpattern.rsplit(":", 1)
    self._apply_addrspec(addrspec)
    self._apply_portspec(portspec)
    
    # Pre-calculating the integer representation of our mask and masked
    # address. These are used by our is_match() method to compare ourselves to
    # other addresses.
    
    if self.address_type == AddressType.WILDCARD:
      # is_match() will short circuit so these are unused
      self._mask_bin = self._addr_bin = None
    else:
      self._mask_bin = int(stem.util.connection.get_address_binary(self.mask), 2)
      self._addr_bin = int(stem.util.connection.get_address_binary(self.address), 2) & self._mask_bin
    
    self._str_representation = None
  
  def is_address_wildcard(self):
    """
    True if we'll match against any address for our type, False otherwise.
    
    :returns: bool for if our address matching is a wildcard
    """
    
    return self.address_type == AddressType.WILDCARD or self.masked_bits == 0
  
  def is_port_wildcard(self):
    """
    True if we'll match against any port, False otherwise.
    
    :returns: bool for if our port matching is a wildcard
    """
    
    return self.min_port in (0, 1) and self.max_port == 65535
  
  def is_match(self, address = None, port = None):
    """
    True if we match against the given destination, False otherwise. If the
    address or port is omitted then that'll only match against a wildcard.
    
    :param str address: IPv4 or IPv6 address (with or without brackets)
    :param int port: port number
    
    :returns: bool indicating if we match against this destination
    
    :raises: ValueError if provided with a malformed address or port
    """
    
    # validate our input and check if the argumement doens't match our address type
    if address != None:
      if stem.util.connection.is_valid_ip_address(address):
        if self.address_type == AddressType.IPv6: return False
      elif stem.util.connection.is_valid_ipv6_address(address, allow_brackets = True):
        if self.address_type == AddressType.IPv4: return False
        
        address = address.lstrip("[").rstrip("]")
      else:
        raise ValueError("'%s' isn't a valid IPv4 or IPv6 address" % address)
    
    if port != None and not stem.util.connection.is_valid_port(port):
      raise ValueError("'%s' isn't a valid port" % port)
    
    if address is None:
      # Note that this isn't the exact same as is_address_wildcard(). We only
      # accept a None address if we got an '*' for our address. Not an IPv4 or
      # IPv6 address that accepts everything (ex '0.0.0.0/0'). This is because
      # those still only match against that type (ie, an IPv4 /0 won't match
      # against IPv6 addresses).
      
      if self.address_type != AddressType.WILDCARD:
        return False
    elif not self.is_address_wildcard():
      # Already got the integer representation of our mask and our address
      # with the mask applied. Just need to check if this address with the
      # mask applied matches.
      
      comparison_addr_bin = int(stem.util.connection.get_address_binary(address), 2)
      comparison_addr_bin &= self._mask_bin
      if self._addr_bin != comparison_addr_bin: return False
    
    if not self.is_port_wildcard():
      if port is None:
        return False
      elif port < self.min_port or port > self.max_port:
        return False
    
    return True
  
  def __str__(self):
    """
    Provides the string representation of our policy. This does not
    necessarily match the rule that we were constructed from (due to things
    like IPv6 address collapsing or the multiple representations that our mask
    can have). However, it is a valid that would be accepted by our constructor
    to re-create this rule.
    """
    
    if self._str_representation is None:
      label = "accept " if self.is_accept else "reject "
      
      if self.address_type == AddressType.WILDCARD:
        label += "*:"
      else:
        if self.address_type == AddressType.IPv4:
          label += self.address
        else:
          label += "[%s]" % self.address
        
        # Including our mask label as follows...
        # - exclde our mask if it doesn't do anything
        # - use our masked bit count if we can
        # - use the mask itself otherwise
        
        if self.mask in (stem.util.connection.FULL_IPv4_MASK, stem.util.connection.FULL_IPv6_MASK):
          label += ":"
        elif not self.masked_bits is None:
          label += "/%i:" % self.masked_bits
        else:
          label += "/%s:" % self.mask
      
      if self.is_port_wildcard():
        label += "*"
      elif self.min_port == self.max_port:
        label += str(self.min_port)
      else:
        label += "%i-%i" % (self.min_port, self.max_port)
      
      self._str_representation = label
    
    return self._str_representation
  
  def _apply_addrspec(self, addrspec):
    # Parses the addrspec...
    # addrspec ::= "*" | ip4spec | ip6spec
    
    if "/" in addrspec:
      self.address, addr_extra = addrspec.split("/", 1)
    else:
      self.address, addr_extra = addrspec, None
    
    if addrspec == "*":
      self.address_type = AddressType.WILDCARD
      self.address = self.mask = self.masked_bits = None
    elif stem.util.connection.is_valid_ip_address(self.address):
      # ipv4spec ::= ip4 | ip4 "/" num_ip4_bits | ip4 "/" ip4mask
      # ip4 ::= an IPv4 address in dotted-quad format
      # ip4mask ::= an IPv4 mask in dotted-quad format
      # num_ip4_bits ::= an integer between 0 and 32
      
      self.address_type = AddressType.IPv4
      
      if addr_extra is None:
        self.mask = stem.util.connection.FULL_IPv4_MASK
        self.masked_bits = 32
      elif stem.util.connection.is_valid_ip_address(addr_extra):
        # provided with an ip4mask
        self.mask = addr_extra
        
        try:
          self.masked_bits = stem.util.connection.get_masked_bits(addr_extra)
        except ValueError:
          # mask can't be represented as a number of bits (ex. "255.255.0.255")
          self.masked_bits = None
      elif addr_extra.isdigit():
        # provided with a num_ip4_bits
        self.mask = stem.util.connection.get_mask(int(addr_extra))
        self.masked_bits = int(addr_extra)
      else:
        raise ValueError("The '%s' isn't a mask nor number of bits: %s" % (addr_extra, self.rule))
    elif self.address.startswith("[") and self.address.endswith("]") and \
      stem.util.connection.is_valid_ipv6_address(self.address[1:-1]):
      # ip6spec ::= ip6 | ip6 "/" num_ip6_bits
      # ip6 ::= an IPv6 address, surrounded by square brackets.
      # num_ip6_bits ::= an integer between 0 and 128
      
      self.address = stem.util.connection.expand_ipv6_address(self.address[1:-1].upper())
      self.address_type = AddressType.IPv6
      
      if addr_extra is None:
        self.mask = stem.util.connection.FULL_IPv6_MASK
        self.masked_bits = 128
      elif addr_extra.isdigit():
        # provided with a num_ip6_bits
        self.mask = stem.util.connection.get_mask_ipv6(int(addr_extra))
        self.masked_bits = int(addr_extra)
      else:
        raise ValueError("The '%s' isn't a number of bits: %s" % (addr_extra, self.rule))
    else:
      raise ValueError("Address isn't a wildcard, IPv4, or IPv6 address: %s" % self.rule)
  
  def _apply_portspec(self, portspec):
    # Parses the portspec...
    # portspec ::= "*" | port | port "-" port
    # port ::= an integer between 1 and 65535, inclusive.
    #
    # Due to a tor bug the spec says that we should accept port of zero, but
    # connections to port zero are never permitted.
    
    if portspec == "*":
      self.min_port, self.max_port = 1, 65535
    elif portspec.isdigit():
      # provided with a single port
      if stem.util.connection.is_valid_port(portspec, allow_zero = True):
        self.min_port = self.max_port = int(portspec)
      else:
        raise ValueError("'%s' isn't within a valid port range: %s" % (portspec, self.rule))
    elif "-" in portspec:
      # provided with a port range
      port_comp = portspec.split("-", 1)
      
      if stem.util.connection.is_valid_port(port_comp, allow_zero = True):
        self.min_port = int(port_comp[0])
        self.max_port = int(port_comp[1])
        
        if self.min_port > self.max_port:
          raise ValueError("Port range has a lower bound that's greater than its upper bound: %s" % self.rule)
      else:
        raise ValueError("Malformed port range: %s" % self.rule)
    else:
      raise ValueError("Port value isn't a wildcard, integer, or range: %s" % self.rule)

class ExitPolicy(object):
  """
  Policy for the destinations that a relay allows or denies exiting to. This
  is, in effect, simply a list of ExitPolicyRule entries.
  """
  
  def __init__(self):
    self._policies = []
    self.summary = ""

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
        self._policies.append(ExitPolicyRule(new_entry))
    else:
      self._policies.append(ExitPolicyRule(rule_entry))

  def get_summary(self):
    """
    Provides a summary description of the policy chain similar to the
    consensus. This excludes entries that don't cover all ips, and is either
    a whitelist or blacklist policy based on the final entry. 
    """
    
    # determines if we're a whitelist or blacklist
    is_whitelist = False # default in case we don't have a catch-all policy at the end
    
    for policy in self._policies:
      if policy.is_address_wildcard() and policy.is_port_wildcard():
        is_whitelist = not policy.is_accept
        break
      
    # Iterates over the policys and adds the the ports we'll return (ie, allows
    # if a whitelist and rejects if a blacklist). Regardless of a port's
    # allow/reject policy, all further entries with that port are ignored since
    # policies respect the first matching policy.
    
    display_ports, skip_ports = [], []
    
    for policy in self._policies:
      if not policy.is_address_wildcard(): continue
      
      if policy.min_port == policy.max_port:
        port_range = [policy.min_port]
      else:
        port_range = range(policy.min_port, policy.max_port + 1)
        
      for port in port_range:
        if port in skip_ports: continue
        
        # if accept + whitelist or reject + blacklist then add
        if policy.is_accept == is_whitelist:
          display_ports.append(port)
          
        # all further entries with this port are to be ignored
        skip_ports.append(port)
        
    # gets a list of the port ranges
    if display_ports:
      display_ranges, temp_range = [], []
      display_ports.sort()
      display_ports.append(None) # ending item to include last range in loop
      
      for port in display_ports:
        if not temp_range or temp_range[-1] + 1 == port:
          temp_range.append(port)
        else:
          if len(temp_range) > 1:
            display_ranges.append("%i-%i" % (temp_range[0], temp_range[-1]))
          else:
            display_ranges.append(str(temp_range[0]))
            
          temp_range = [port]
    else:
      # everything for the inverse
      is_whitelist = not is_whitelist
      display_ranges = ["1-65535"]
      
    # constructs the summary string
    label_prefix = "accept " if is_whitelist else "reject "
    
    self.summary = (label_prefix + ", ".join(display_ranges)).strip()
    
  def is_exiting_allowed(self):
    """
    Provides true if the policy allows exiting whatsoever, false otherwise.
    """
    for policy in self._policies:
      if policy.is_accept: return True
      elif policy.is_address_wildcard() and policy.is_port_wildcard(): return False
    
  def check(self, ip_address, port):
    """
    Checks if the rule chain allows exiting to this address, returning true if
    so and false otherwise.
    """
    
    for policy in self._policies:
      if policy.is_match(ip_address, port):
        return policy.is_accept
        
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
    return ', '.join([str(policy) for policy in self._policies])
  
class MicrodescriptorExitPolicy:
  """
  Microdescriptor exit policy -  'accept 53,80,443'
  """

  def __init__(self, summary):
    self.ports = []
    self.is_accept = None
    self.summary = summary
    
    # sanitize the input a bit, cleaning up tabs and stripping quotes
    summary = self.summary.replace("\\t", " ").replace("\"", "")
    
    self.is_accept = summary.startswith("accept")
    
    # strips off "accept " or "reject " and extra spaces
    summary = summary[7:].replace(" ", "")
    
    for ports in summary.split(','):
      if '-' in ports:
        port_range = ports.split("-", 1)
        if not stem.util.connection.is_valid_port(port_range):
          raise ValueError("Invaid port range")
        self.ports.append(range(int(port_range[2])), int(port_range[1]))
      if not stem.util.connection.is_valid_port(ports):
          raise ValueError("Invalid port range")
      self.ports.append(int(ports))
      
  def check(self, ip_address=None, port=None):
    # stem is intelligent about the arguments
    if not port:
      if not '.' in str(ip_address):
        port = ip_address
    
    port = int(port)
    
    if port in self.ports:
      # its a list of accepted ports
      if self.is_accept:
        return True
      else:
        return False
    else:
      # its a list of rejected ports
      if not self.is_accept:
        return True
      else:
        return False
    
  def __str__(self):
    return self.summary

  def ports(self):
    return self.ports

  def is_accept(self):
    return self.is_accept

