# Copyright 2012-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Representation of tor exit policies. These can be easily used to check if
exiting to a destination is permissible or not. For instance...

::

  >>> from stem.exit_policy import ExitPolicy, MicroExitPolicy
  >>> policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
  >>> print(policy)
  accept *:80, accept *:443, reject *:*
  >>> print(policy.summary())
  accept 80, 443
  >>> policy.can_exit_to('75.119.206.243', 80)
  True

  >>> policy = MicroExitPolicy('accept 80,443')
  >>> print(policy)
  accept 80,443
  >>> policy.can_exit_to('75.119.206.243', 80)
  True

::

  ExitPolicy - Exit policy for a Tor relay
    |- MicroExitPolicy - Microdescriptor exit policy
    |
    |- can_exit_to - check if exiting to this destination is allowed or not
    |- is_exiting_allowed - check if any exiting is allowed
    |- summary - provides a short label, similar to a microdescriptor
    |- has_private - checks if policy has anything expanded from the 'private' keyword
    |- strip_private - provides a copy of the policy without 'private' entries
    |- has_default - checks if policy ends with the defaultly appended suffix
    |- strip_default - provides a copy of the policy without the default suffix
    |- __str__  - string representation
    +- __iter__ - ExitPolicyRule entries that this contains

  ExitPolicyRule - Single rule of an exit policy chain
    |- MicroExitPolicyRule - Single rule for a microdescriptor policy
    |
    |- is_address_wildcard - checks if we'll accept any address
    |- is_port_wildcard - checks if we'll accept any port
    |- get_address_type - provides the protocol our ip address belongs to
    |- is_match - checks if we match a given destination
    |- get_mask - provides the address representation of our mask
    |- get_masked_bits - provides the bit representation of our mask
    |- is_default - flag indicating if this was part of the default end of a policy
    |- is_private - flag indicating if this was expanded from a 'private' keyword
    +- __str__ - string representation for this rule

.. data:: AddressType (enum)

  Enumerations for IP address types that can be in an exit policy.

  ============ ===========
  AddressType  Description
  ============ ===========
  **WILDCARD** any address of either IPv4 or IPv6
  **IPv4**     IPv4 address
  **IPv6**     IPv6 address
  ============ ===========
"""

import functools
import zlib

import stem.util
import stem.util.connection
import stem.util.enum
import stem.util.str_tools

from typing import Any, Iterator, List, Optional, Sequence, Set, Union

AddressType = stem.util.enum.Enum(('WILDCARD', 'Wildcard'), ('IPv4', 'IPv4'), ('IPv6', 'IPv6'))

# Addresses aliased by the 'private' policy. From the tor man page...
#
# To specify all internal and link-local networks (including 0.0.0.0/8,
# 169.254.0.0/16, 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8, and 172.16.0.0/12),
# you can use the 'private' alias instead of an address.

PRIVATE_ADDRESSES = (
  '0.0.0.0/8',
  '169.254.0.0/16',
  '127.0.0.0/8',
  '192.168.0.0/16',
  '10.0.0.0/8',
  '172.16.0.0/12',
)


def _flag_private_rules(rules: Sequence['ExitPolicyRule']) -> None:
  """
  Determine if part of our policy was expanded from the 'private' keyword. This
  doesn't differentiate if this actually came from the 'private' keyword or a
  series of rules exactly matching it.
  """

  matches = []  # find all possible starting indexes

  for i, rule in enumerate(rules):
    if i + len(PRIVATE_ADDRESSES) > len(rules):
      break

    rule_str = '%s/%s' % (rule.address, rule.get_masked_bits())

    if rule_str == PRIVATE_ADDRESSES[0]:
      matches.append(i)

  for start_index in matches:
    # To match the private policy the following must all be true...
    #
    #   * series of addresses and bit masks match PRIVATE_ADDRESSES
    #   * all rules have the same port range
    #   * all rules have the same acceptance (all accept or reject entries)
    #
    # The last rule is dynamically based on the relay's public address.

    last_index = start_index + len(PRIVATE_ADDRESSES)
    rule_set = rules[start_index:last_index]
    last_rule = rules[last_index] if len(rules) > last_index else None
    is_match = True

    min_port, max_port = rule_set[0].min_port, rule_set[0].max_port
    is_accept = rule_set[0].is_accept

    for i, rule in enumerate(rule_set):
      rule_str = '%s/%s' % (rule.address, rule.get_masked_bits())

      if rule_str != PRIVATE_ADDRESSES[i] or rule.min_port != min_port or rule.max_port != max_port or rule.is_accept != is_accept:
        is_match = False
        break

    if is_match:
      for rule in rule_set:
        rule._is_private = True

      if last_rule and not last_rule.is_address_wildcard() and last_rule.min_port == min_port and last_rule.max_port == max_port and last_rule.is_accept == is_accept:
        last_rule._is_private = True


def _flag_default_rules(rules: Sequence['ExitPolicyRule']) -> None:
  """
  Determine if part of our policy ends with the defaultly appended suffix.
  """

  if len(rules) >= len(DEFAULT_POLICY_RULES):
    rules_suffix = tuple(rules[-len(DEFAULT_POLICY_RULES):])

    if rules_suffix == DEFAULT_POLICY_RULES:
      for rule in rules_suffix:
        rule._is_default_suffix = True


class ExitPolicy(object):
  """
  Policy for the destinations that a relay allows or denies exiting to. This
  is, in effect, just a list of :class:`~stem.exit_policy.ExitPolicyRule`
  entries.

  :param list rules: **str** or :class:`~stem.exit_policy.ExitPolicyRule`
    entries that make up this policy
  """

  def __init__(self, *rules: Union[str, 'stem.exit_policy.ExitPolicyRule']) -> None:
    # sanity check the types

    self._input_rules = None  # type: Optional[Union[bytes, Sequence[Union[str, bytes, stem.exit_policy.ExitPolicyRule]]]]

    for rule in rules:
      if not isinstance(rule, (bytes, str)) and not isinstance(rule, ExitPolicyRule):
        raise TypeError('Exit policy rules can only contain strings or ExitPolicyRules, got a %s (%s)' % (type(rule), rules))

    # Unparsed representation of the rules we were constructed with. Our
    # _get_rules() method consumes this to provide ExitPolicyRule instances.
    # This is lazily evaluated so we don't need to actually parse the exit
    # policy if it's never used.

    is_all_str = True

    for rule in rules:
      if not isinstance(rule, (bytes, str)):
        is_all_str = False

    if rules and is_all_str:
      byte_rules = [stem.util.str_tools._to_bytes(r) for r in rules]  # type: ignore
      self._input_rules = zlib.compress(b','.join(byte_rules))
    else:
      self._input_rules = rules

    self._policy_str = None  # type: Optional[str]
    self._rules = None  # type: List[stem.exit_policy.ExitPolicyRule]
    self._hash = None  # type: Optional[int]

    # Result when no rules apply. According to the spec policies default to 'is
    # allowed', but our microdescriptor policy subclass might want to change
    # this.

    self._is_allowed_default = True

  @functools.lru_cache()
  def can_exit_to(self, address: Optional[str] = None, port: Optional[int] = None, strict: bool = False) -> bool:
    """
    Checks if this policy allows exiting to a given destination or not. If the
    address or port is omitted then this will check if we're allowed to exit to
    any instances of the defined address or port.

    :param str address: IPv4 or IPv6 address (with or without brackets)
    :param int port: port number
    :param bool strict: if the address or port is excluded then check if we can
      exit to **all** instances of the defined address or port

    :returns: **True** if exiting to this destination is allowed, **False** otherwise
    """

    if not self.is_exiting_allowed():
      return False

    for rule in self._get_rules():
      if rule.is_match(address, port, strict):
        return rule.is_accept

    return self._is_allowed_default

  @functools.lru_cache()
  def is_exiting_allowed(self) -> bool:
    """
    Provides **True** if the policy allows exiting whatsoever, **False**
    otherwise.
    """

    rejected_ports = set()  # type: Set[int]

    for rule in self._get_rules():
      if rule.is_accept:
        for port in range(rule.min_port, rule.max_port + 1):
          if port not in rejected_ports:
            return True
      elif rule.is_address_wildcard():
        if rule.is_port_wildcard():
          return False
        else:
          rejected_ports.update(range(rule.min_port, rule.max_port + 1))

    return self._is_allowed_default

  @functools.lru_cache()
  def summary(self) -> str:
    """
    Provides a short description of our policy chain, similar to a
    microdescriptor. This excludes entries that don't cover all IP
    addresses, and is either white-list or blacklist policy based on
    the final entry. For instance...

    ::

      >>> policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
      >>> policy.summary()
      'accept 80, 443'

      >>> policy = ExitPolicy('accept *:443', 'reject *:1-1024', 'accept *:*')
      >>> policy.summary()
      'reject 1-442, 444-1024'

    :returns: **str** with a concise summary for our policy
    """

    # determines if we're a white-list or blacklist
    is_whitelist = not self._is_allowed_default

    for rule in self._get_rules():
      if rule.is_address_wildcard() and rule.is_port_wildcard():
        is_whitelist = not rule.is_accept
        break

    # Iterates over the policies and adds the the ports we'll return (ie,
    # allows if a white-list and rejects if a blacklist). Regardless of a
    # port's allow/reject policy, all further entries with that port are
    # ignored since policies respect the first matching policy.

    display_ports, skip_ports = [], set()

    for rule in self._get_rules():
      if not rule.is_address_wildcard():
        continue
      elif rule.is_port_wildcard():
        break

      for port in range(rule.min_port, rule.max_port + 1):
        if port in skip_ports:
          continue

        # if accept + white-list or reject + blacklist then add
        if rule.is_accept == is_whitelist:
          display_ports.append(port)

        # all further entries with this port should be ignored
        skip_ports.add(port)

    # convert port list to a list of ranges (ie, ['1-3'] rather than [1, 2, 3])
    if display_ports:
      display_ranges = []
      temp_range = []  # type: List[int]
      display_ports.sort()
      display_ports.append(None)  # ending item to include last range in loop

      for port in display_ports:
        if not temp_range or temp_range[-1] + 1 == port:
          temp_range.append(port)
        else:
          if len(temp_range) > 1:
            display_ranges.append('%i-%i' % (temp_range[0], temp_range[-1]))
          else:
            display_ranges.append(str(temp_range[0]))

          temp_range = [port]
    else:
      # everything for the inverse
      is_whitelist = not is_whitelist
      display_ranges = ['1-65535']

    # constructs the summary string
    label_prefix = 'accept ' if is_whitelist else 'reject '

    return (label_prefix + ', '.join(display_ranges)).strip()

  def has_private(self) -> bool:
    """
    Checks if we have any rules expanded from the 'private' keyword. Tor
    appends these by default to the start of the policy and includes a dynamic
    address (the relay's public IP).

    .. versionadded:: 1.3.0

    :returns: **True** if we have any private rules expanded from the 'private'
      keyword, **False** otherwise
    """

    for rule in self._get_rules():
      if rule.is_private():
        return True

    return False

  def strip_private(self) -> 'ExitPolicy':
    """
    Provides a copy of this policy without 'private' policy entries.

    .. versionadded:: 1.3.0

    :returns: **ExitPolicy** without private rules
    """

    return ExitPolicy(*[rule for rule in self._get_rules() if not rule.is_private()])

  def has_default(self) -> bool:
    """
    Checks if we have the default policy suffix.

    .. versionadded:: 1.3.0

    :returns: **True** if we have the default policy suffix, **False** otherwise
    """

    for rule in self._get_rules():
      if rule.is_default():
        return True

    return False

  def strip_default(self) -> 'ExitPolicy':
    """
    Provides a copy of this policy without the default policy suffix.

    .. versionadded:: 1.3.0

    :returns: **ExitPolicy** without default rules
    """

    return ExitPolicy(*[rule for rule in self._get_rules() if not rule.is_default()])

  def _get_rules(self) -> Sequence['stem.exit_policy.ExitPolicyRule']:
    # Local reference to our input_rules so this can be lock free. Otherwise
    # another thread might unset our input_rules while processing them.

    input_rules = self._input_rules

    if self._rules is None and input_rules is not None:
      rules = []  # type: List[stem.exit_policy.ExitPolicyRule]
      is_all_accept, is_all_reject = True, True
      decompressed_rules = None  # type: Optional[Sequence[Union[str, bytes, stem.exit_policy.ExitPolicyRule]]]

      if isinstance(input_rules, bytes):
        decompressed_rules = zlib.decompress(input_rules).split(b',')
      else:
        decompressed_rules = input_rules

      for rule_val in decompressed_rules:
        if isinstance(rule_val, bytes):
          rule_val = stem.util.str_tools._to_unicode(rule_val)

        if isinstance(rule_val, str):
          if not rule_val.strip():
            continue

          rule = ExitPolicyRule(rule_val.strip())
        elif isinstance(rule_val, stem.exit_policy.ExitPolicyRule):
          rule = rule_val
        else:
          raise TypeError('BUG: unexpected type within decompressed policy: %s (%s)' % (stem.util.str_tools._to_unicode(rule_val), type(rule_val).__name__))

        if rule.is_accept:
          is_all_reject = False
        else:
          is_all_accept = False

        rules.append(rule)

        if rule.is_address_wildcard() and rule.is_port_wildcard():
          break  # this is a catch-all, no reason to include more

      # If we only have one kind of entry *and* end with a wildcard then
      # we might as well use the simpler version. For instance...
      #
      #   reject *:80, reject *:443, reject *:*
      #
      # ... could also be represented as simply...
      #
      #   reject *:*
      #
      # This mostly comes up with reject-all policies because the
      # 'reject private:*' appends an extra seven rules that have no
      # effect.

      if rules and (rules[-1].is_address_wildcard() and rules[-1].is_port_wildcard()):
        if is_all_accept:
          rules = [ExitPolicyRule('accept *:*')]
        elif is_all_reject:
          rules = [ExitPolicyRule('reject *:*')]

      _flag_private_rules(rules)
      _flag_default_rules(rules)

      self._rules = rules
      self._input_rules = None

    return self._rules

  def __len__(self) -> int:
    return len(self._get_rules())

  def __iter__(self) -> Iterator['stem.exit_policy.ExitPolicyRule']:
    for rule in self._get_rules():
      yield rule

  def __str__(self) -> str:
    if self._policy_str is None:
      self._policy_str = ', '.join([str(rule) for rule in self._get_rules()])

    return self._policy_str

  def __hash__(self) -> int:
    if self._hash is None:
      my_hash = 0

      for rule in self._get_rules():
        my_hash *= 1024
        my_hash += hash(rule)

      self._hash = my_hash

    return self._hash

  def __eq__(self, other: Any) -> bool:
    return hash(self) == hash(other) if isinstance(other, ExitPolicy) else False

  def __ne__(self, other: Any) -> bool:
    return not self == other


class MicroExitPolicy(ExitPolicy):
  """
  Exit policy provided by the microdescriptors. This is a distilled version of
  a normal :class:`~stem.exit_policy.ExitPolicy` contains, just consisting of a
  list of ports that are either accepted or rejected. For instance...

  ::

    accept 80,443       # only accepts common http ports
    reject 1-1024       # only accepts non-privileged ports

  Since these policies are a subset of the exit policy information (lacking IP
  ranges) clients can only use them to guess if a relay will accept traffic or
  not. To quote the `dir-spec <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_ (section 3.2.1)...

  ::

    With microdescriptors, clients don't learn exact exit policies:
    clients can only guess whether a relay accepts their request, try the
    BEGIN request, and might get end-reason-exit-policy if they guessed
    wrong, in which case they'll have to try elsewhere.

  :var bool is_accept: **True** if these are ports that we accept, **False** if
    they're ports that we reject

  :param str policy: policy string that describes this policy
  """

  def __init__(self, policy: str) -> None:
    # Microdescriptor policies are of the form...
    #
    #   MicrodescriptrPolicy ::= ("accept" / "reject") SP PortList NL
    #   PortList ::= PortOrRange
    #   PortList ::= PortList "," PortOrRange
    #   PortOrRange ::= INT "-" INT / INT

    policy_str = policy

    if policy.startswith('accept'):
      self.is_accept = True
    elif policy.startswith('reject'):
      self.is_accept = False
    else:
      raise ValueError("A microdescriptor exit policy must start with either 'accept' or 'reject': %s" % policy)

    policy = policy[6:]

    if not policy.startswith(' '):
      raise ValueError('A microdescriptor exit policy should have a space separating accept/reject from its port list: %s' % policy_str)

    policy = policy.lstrip()

    # convert our port list into MicroExitPolicyRule
    rules = []

    for port_entry in policy.split(','):
      if '-' in port_entry:
        min_port, max_port = port_entry.split('-', 1)
      else:
        min_port = max_port = port_entry

      if not stem.util.connection.is_valid_port(min_port) or \
         not stem.util.connection.is_valid_port(max_port):
        raise ValueError("'%s' is an invalid port range" % port_entry)

      rules.append(MicroExitPolicyRule(self.is_accept, int(min_port), int(max_port)))

    super(MicroExitPolicy, self).__init__(*rules)
    self._is_allowed_default = not self.is_accept
    self._policy_str = policy_str

  def __str__(self) -> str:
    return self._policy_str

  def __hash__(self) -> int:
    return hash(str(self))

  def __eq__(self, other: Any) -> bool:
    return hash(self) == hash(other) if isinstance(other, MicroExitPolicy) else False

  def __ne__(self, other: Any) -> bool:
    return not self == other


class ExitPolicyRule(object):
  """
  Single rule from the user's exit policy. These rules are chained together to
  form complete policies that describe where a relay will and will not allow
  traffic to exit.

  The format of these rules are formally described in the `dir-spec
  <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_ as an
  'exitpattern'. Note that while these are similar to tor's man page entry for
  ExitPolicies, it's not the exact same. An exitpattern is better defined and
  stricter in what it'll accept. For instance, ports are not optional and it
  does not contain the 'private' alias.

  This should be treated as an immutable object.

  .. versionchanged:: 1.5.0
     Support for 'accept6/reject6' entries and '\\*4/6' wildcards.

  :var bool is_accept: indicates if exiting is allowed or disallowed

  :var str address: address that this rule is for

  :var int min_port: lower end of the port range that we include (inclusive)
  :var int max_port: upper end of the port range that we include (inclusive)

  :param str rule: exit policy rule to be parsed

  :raises: **ValueError** if input isn't a valid tor exit policy rule
  """

  def __init__(self, rule: str) -> None:
    # policy ::= "accept[6]" exitpattern | "reject[6]" exitpattern
    # exitpattern ::= addrspec ":" portspec

    rule = stem.util.str_tools._to_unicode(rule)

    self.is_accept = rule.startswith('accept')
    is_ipv6_only = rule.startswith('accept6') or rule.startswith('reject6')

    if rule.startswith('accept6') or rule.startswith('reject6'):
      exitpattern = rule[7:]
    elif rule.startswith('accept') or rule.startswith('reject'):
      exitpattern = rule[6:]
    else:
      raise ValueError("An exit policy must start with either 'accept[6]' or 'reject[6]': %s" % rule)

    if not exitpattern.startswith(' '):
      raise ValueError('An exit policy should have a space separating its accept/reject from the exit pattern: %s' % rule)

    exitpattern = exitpattern.lstrip()

    if ':' not in exitpattern or ']' in exitpattern.rsplit(':', 1)[1]:
      raise ValueError("An exitpattern must be of the form 'addrspec:portspec': %s" % rule)

    self.address = None  # type: Optional[str]
    self._address_type = None  # type: Optional[stem.exit_policy.AddressType]
    self._masked_bits = None  # type: Optional[int]
    self.min_port = self.max_port = None  # type: Optional[int]
    self._hash = None  # type: Optional[int]

    # Our mask in ip notation (ex. '255.255.255.0'). This is only set if we
    # either have a custom mask that can't be represented by a number of bits,
    # or the user has called mask(), lazily loading this.

    self._mask = None  # type: Optional[str]

    # Malformed exit policies are rejected, but there's an exception where it's
    # just skipped: when an accept6/reject6 rule has an IPv4 address...
    #
    #   "Using an IPv4 address with accept6 or reject6 is ignored and generates
    #   a warning."

    self._skip_rule = False

    addrspec, portspec = exitpattern.rsplit(':', 1)
    self._apply_addrspec(rule, addrspec, is_ipv6_only)
    self._apply_portspec(rule, portspec)

    # Flags to indicate if this rule seems to be expanded from the 'private'
    # keyword or tor's default policy suffix.

    self._is_private = False
    self._is_default_suffix = False

  def is_address_wildcard(self) -> bool:
    """
    **True** if we'll match against **any** address, **False** otherwise.

    Note that this is different than \\*4, \\*6, or '/0' address which are
    wildcards for only either IPv4 or IPv6.

    :returns: **bool** for if our address matching is a wildcard
    """

    return self._address_type == _address_type_to_int(AddressType.WILDCARD)

  def is_port_wildcard(self) -> bool:
    """
    **True** if we'll match against any port, **False** otherwise.

    :returns: **bool** for if our port matching is a wildcard
    """

    return self.min_port in (0, 1) and self.max_port == 65535

  def is_match(self, address: Optional[str] = None, port: Optional[int] = None, strict: bool = False) -> bool:
    """
    **True** if we match against the given destination, **False** otherwise. If
    the address or port is omitted then this will check if we're allowed to
    exit to any instances of the defined address or port.

    :param str address: IPv4 or IPv6 address (with or without brackets)
    :param int port: port number
    :param bool strict: if the address or port is excluded then check if we can
      exit to **all** instances of the defined address or port

    :returns: **bool** indicating if we match against this destination

    :raises: **ValueError** if provided with a malformed address or port
    """

    if self._skip_rule:
      return False

    # validate our input and check if the argument doesn't match our address type

    if address is not None:
      address_type = self.get_address_type()

      if stem.util.connection.is_valid_ipv4_address(address):
        if address_type == AddressType.IPv6:
          return False
      elif stem.util.connection.is_valid_ipv6_address(address, allow_brackets = True):
        if address_type == AddressType.IPv4:
          return False

        address = address.lstrip('[').rstrip(']')
      else:
        raise ValueError("'%s' isn't a valid IPv4 or IPv6 address" % address)

    if port is not None and not stem.util.connection.is_valid_port(port):
      raise ValueError("'%s' isn't a valid port" % port)

    # If we're not matching against an address or port but the rule has one
    # then we're a fuzzy match. When that happens...
    #
    # * If strict and a reject rule then we're a match ('can exit to *all* instances').
    # * If not strict and an accept rule then match ('an exit ot *any* instance').

    fuzzy_match = False

    if not self.is_address_wildcard():
      # Already got the integer representation of our mask and our address
      # with the mask applied. Just need to check if this address with the
      # mask applied matches.

      if address is None:
        fuzzy_match = True
      else:
        comparison_addr_bin = stem.util.connection.address_to_int(address)
        comparison_addr_bin &= self._get_mask_bin()

        if self._get_address_bin() != comparison_addr_bin:
          return False

    if not self.is_port_wildcard():
      if port is None:
        fuzzy_match = True
      elif port < self.min_port or port > self.max_port:
        return False

    if fuzzy_match:
      return strict != self.is_accept
    else:
      return True

  def get_address_type(self) -> AddressType:
    """
    Provides the :data:`~stem.exit_policy.AddressType` for our policy.

    :returns: :data:`~stem.exit_policy.AddressType` for the type of address that we have
    """

    return _int_to_address_type(self._address_type)

  def get_mask(self, cache: bool = True) -> str:
    """
    Provides the address represented by our mask. This is **None** if our
    address type is a wildcard.

    :param bool cache: caches the result if **True**

    :returns: str of our subnet mask for the address (ex. '255.255.255.0')
    """

    # Lazy loading our mask because it is very infrequently requested. There's
    # no reason to usually use memory for it.

    if not self._mask:
      address_type = self.get_address_type()

      if address_type == AddressType.WILDCARD:
        mask = None
      elif address_type == AddressType.IPv4:
        mask = stem.util.connection.get_mask_ipv4(self._masked_bits)
      elif address_type == AddressType.IPv6:
        mask = stem.util.connection.get_mask_ipv6(self._masked_bits)

      if not cache:
        return mask

      self._mask = mask

    return self._mask

  def get_masked_bits(self) -> int:
    """
    Provides the number of bits our subnet mask represents. This is **None** if
    our mask can't have a bit representation.

    :returns: int with the bit representation of our mask
    """

    return self._masked_bits

  def is_private(self) -> bool:
    """
    Checks if this rule was expanded from the 'private' policy keyword.

    .. versionadded:: 1.3.0

    :returns: **True** if this rule was expanded from the 'private' keyword, **False** otherwise.
    """

    return self._is_private

  def is_default(self) -> bool:
    """
    Checks if this rule belongs to the default exit policy suffix.

    .. versionadded:: 1.3.0

    :returns: **True** if this rule was part of the default end of a policy, **False** otherwise.
    """

    return self._is_default_suffix

  @functools.lru_cache()
  def __str__(self) -> str:
    """
    Provides the string representation of our policy. This does not
    necessarily match the rule that we were constructed from (due to things
    like IPv6 address collapsing or the multiple representations that our mask
    can have). However, it is a valid that would be accepted by our constructor
    to re-create this rule.
    """

    label = 'accept ' if self.is_accept else 'reject '

    if self.is_address_wildcard():
      label += '*:'
    else:
      address_type = self.get_address_type()

      if address_type == AddressType.IPv4:
        label += self.address
      else:
        label += '[%s]' % self.address

      # Including our mask label as follows...
      # - exclude our mask if it doesn't do anything
      # - use our masked bit count if we can
      # - use the mask itself otherwise

      if (address_type == AddressType.IPv4 and self._masked_bits == 32) or \
         (address_type == AddressType.IPv6 and self._masked_bits == 128):
        label += ':'
      elif self._masked_bits is not None:
        label += '/%i:' % self._masked_bits
      else:
        label += '/%s:' % self.get_mask()

    if self.is_port_wildcard():
      label += '*'
    elif self.min_port == self.max_port:
      label += str(self.min_port)
    else:
      label += '%i-%i' % (self.min_port, self.max_port)

    return label

  @functools.lru_cache()
  def _get_mask_bin(self) -> int:
    # provides an integer representation of our mask

    return int(stem.util.connection._address_to_binary(self.get_mask(False)), 2)

  @functools.lru_cache()
  def _get_address_bin(self) -> int:
    # provides an integer representation of our address

    return stem.util.connection.address_to_int(self.address) & self._get_mask_bin()

  def _apply_addrspec(self, rule: str, addrspec: str, is_ipv6_only: bool) -> None:
    # Parses the addrspec...
    # addrspec ::= "*" | ip4spec | ip6spec

    # Expand IPv4 and IPv6 specific wildcards into /0 entries so we have one
    # fewer bizarre special case headaches to deal with.

    if addrspec == '*4':
      addrspec = '0.0.0.0/0'
    elif addrspec == '*6' or (addrspec == '*' and is_ipv6_only):
      addrspec = '[0000:0000:0000:0000:0000:0000:0000:0000]/0'

    if '/' in addrspec:
      self.address, addr_extra = addrspec.split('/', 1)
    else:
      self.address, addr_extra = addrspec, None

    if addrspec == '*':
      self._address_type = _address_type_to_int(AddressType.WILDCARD)
      self.address = self._masked_bits = None
    elif stem.util.connection.is_valid_ipv4_address(self.address):
      # ipv4spec ::= ip4 | ip4 "/" num_ip4_bits | ip4 "/" ip4mask
      # ip4 ::= an IPv4 address in dotted-quad format
      # ip4mask ::= an IPv4 mask in dotted-quad format
      # num_ip4_bits ::= an integer between 0 and 32

      if is_ipv6_only:
        self._skip_rule = True

      self._address_type = _address_type_to_int(AddressType.IPv4)

      if addr_extra is None:
        self._masked_bits = 32
      elif stem.util.connection.is_valid_ipv4_address(addr_extra):
        # provided with an ip4mask
        try:
          self._masked_bits = stem.util.connection._get_masked_bits(addr_extra)
        except ValueError:
          # mask can't be represented as a number of bits (ex. '255.255.0.255')
          self._mask = addr_extra
          self._masked_bits = None
      elif addr_extra.isdigit():
        # provided with a num_ip4_bits
        self._masked_bits = int(addr_extra)

        if self._masked_bits < 0 or self._masked_bits > 32:
          raise ValueError('IPv4 masks must be in the range of 0-32 bits')
      else:
        raise ValueError("The '%s' isn't a mask nor number of bits: %s" % (addr_extra, rule))
    elif self.address.startswith('[') and self.address.endswith(']') and \
      stem.util.connection.is_valid_ipv6_address(self.address[1:-1]):
      # ip6spec ::= ip6 | ip6 "/" num_ip6_bits
      # ip6 ::= an IPv6 address, surrounded by square brackets.
      # num_ip6_bits ::= an integer between 0 and 128

      self.address = stem.util.connection.expand_ipv6_address(self.address[1:-1].upper())
      self._address_type = _address_type_to_int(AddressType.IPv6)

      if addr_extra is None:
        self._masked_bits = 128
      elif addr_extra.isdigit():
        # provided with a num_ip6_bits
        self._masked_bits = int(addr_extra)

        if self._masked_bits < 0 or self._masked_bits > 128:
          raise ValueError('IPv6 masks must be in the range of 0-128 bits')
      else:
        raise ValueError("The '%s' isn't a number of bits: %s" % (addr_extra, rule))
    else:
      raise ValueError("'%s' isn't a wildcard, IPv4, or IPv6 address: %s" % (addrspec, rule))

  def _apply_portspec(self, rule: str, portspec: str) -> None:
    # Parses the portspec...
    # portspec ::= "*" | port | port "-" port
    # port ::= an integer between 1 and 65535, inclusive.
    #
    # Due to a tor bug the spec says that we should accept port of zero, but
    # connections to port zero are never permitted.

    if portspec == '*':
      self.min_port, self.max_port = 1, 65535
    elif portspec.isdigit():
      # provided with a single port
      if stem.util.connection.is_valid_port(portspec, allow_zero = True):
        self.min_port = self.max_port = int(portspec)
      else:
        raise ValueError("'%s' isn't within a valid port range: %s" % (portspec, rule))
    elif '-' in portspec:
      # provided with a port range
      port_comp = portspec.split('-', 1)

      if stem.util.connection.is_valid_port(port_comp, allow_zero = True):
        self.min_port = int(port_comp[0])
        self.max_port = int(port_comp[1])

        if self.min_port > self.max_port:
          raise ValueError("Port range has a lower bound that's greater than its upper bound: %s" % rule)
      else:
        raise ValueError('Malformed port range: %s' % rule)
    else:
      raise ValueError("Port value isn't a wildcard, integer, or range: %s" % rule)

  def __hash__(self) -> int:
    if self._hash is None:
      self._hash = stem.util._hash_attr(self, 'is_accept', 'address', 'min_port', 'max_port') * 1024 + hash(self.get_mask(False))

    return self._hash

  def __eq__(self, other: Any) -> bool:
    return hash(self) == hash(other) if isinstance(other, ExitPolicyRule) else False

  def __ne__(self, other: Any) -> bool:
    return not self == other


def _address_type_to_int(address_type: AddressType) -> int:
  return AddressType.index_of(address_type)


def _int_to_address_type(address_type_int: int) -> AddressType:
  return list(AddressType)[address_type_int]


class MicroExitPolicyRule(ExitPolicyRule):
  """
  Lighter weight ExitPolicyRule derivative for microdescriptors.
  """

  def __init__(self, is_accept: bool, min_port: int, max_port: int) -> None:
    self.is_accept = is_accept
    self.address = None  # wildcard address
    self.min_port = min_port
    self.max_port = max_port
    self._skip_rule = False

  def is_address_wildcard(self) -> bool:
    return True

  def get_address_type(self) -> AddressType:
    return AddressType.WILDCARD

  def get_mask(self, cache = True) -> str:
    return None

  def get_masked_bits(self) -> int:
    return None

  def __hash__(self) -> int:
    return stem.util._hash_attr(self, 'is_accept', 'min_port', 'max_port', cache = True)

  def __eq__(self, other: Any) -> bool:
    return hash(self) == hash(other) if isinstance(other, MicroExitPolicyRule) else False

  def __ne__(self, other: Any) -> bool:
    return not self == other


DEFAULT_POLICY_RULES = tuple([ExitPolicyRule(rule) for rule in (
  'reject *:25',
  'reject *:119',
  'reject *:135-139',
  'reject *:445',
  'reject *:563',
  'reject *:1214',
  'reject *:4661-4666',
  'reject *:6346-6429',
  'reject *:6699',
  'reject *:6881-6999',
  'accept *:*',
)])
