import re
import datetime
import StringIO

import stem
import stem.control
import stem.response
import stem.descriptor.router_status_entry

from stem.util import connection, log, str_tools, tor_tools

# Matches keyword=value arguments. This can't be a simple "(.*)=(.*)" pattern
# because some positional arguments, like circuit paths, can have an equal
# sign.

KW_ARG = re.compile("([A-Za-z0-9_]+)=(.*)")

# base message for when we get attributes not covered by our enums

UNRECOGNIZED_ATTR_MSG = "%s event had an unrecognized %%s (%%s). Maybe a new addition to the control protocol? Full Event: '%s'"

class Event(stem.response.ControlMessage):
  """
  Base for events we receive asynchronously, as described in section 4.1 of the
  `control-spec
  <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_.
  
  :var str type: event type
  :var int arrived_at: unix timestamp for when the message arrived
  :var list positional_args: positional arguments of the event
  :var dict keyword_args: key/value arguments of the event
  """
  
  _POSITIONAL_ARGS = ()
  _KEYWORD_ARGS = {}
  _QUOTED = ()
  _SKIP_PARSING = False
  
  # If set then we'll parse anything that looks like a quoted key/value
  # mapping, reguardless of if it shows up in _QUOTED.
  
  _PERMISSIVE_QUOTED_MAPPINGS = False
  
  def _parse_message(self, arrived_at):
    if not str(self).strip():
      raise stem.ProtocolError("Received a blank tor event. Events must at the very least have a type.")
    
    self.type = str(self).split().pop(0)
    self.arrived_at = arrived_at
    
    # if we're a recognized event type then translate ourselves into that subclass
    
    if self.type in EVENT_TYPE_TO_CLASS:
      self.__class__ = EVENT_TYPE_TO_CLASS[self.type]
    
    self.positional_args = []
    self.keyword_args = {}
    
    if not self._SKIP_PARSING:
      self._parse_standard_attr()
    
    self._parse()
  
  def _parse_standard_attr(self):
    """
    Most events are of the form...
    650 *( positional_args ) *( key "=" value )
    
    This parses this standard format, populating our **positional_args** and
    **keyword_args** attributes and creating attributes if it's in our event's
    **_POSITIONAL_ARGS** and **_KEYWORD_ARGS**.
    """
    
    # Whoever decided to allow for quoted attributes in events should be
    # punished. Preferably under some of those maritime laws that allow for
    # flogging. Event parsing was nice until we threw this crap in...
    #
    # Pulling quoted keyword arguments out here. Quoted positonal arguments
    # are handled later.
    
    content = str(self)
    
    if self._PERMISSIVE_QUOTED_MAPPINGS:
      while True:
        match = re.match("^(.*) (\S*)=\"(.*)\"(.*)$", content)
        
        if match:
          prefix, keyword, value, suffix = match.groups()
          content = prefix + suffix
          self.keyword_args[keyword] = value
        else:
          break
    else:
      for keyword in set(self._QUOTED).intersection(set(self._KEYWORD_ARGS.keys())):
        match = re.match("^(.*) %s=\"(.*)\"(.*)$" % keyword, content)
        
        if match:
          prefix, value, suffix = match.groups()
          content = prefix + suffix
          self.keyword_args[keyword] = value
    
    fields = content.split()[1:]
    
    # Tor events contain some number of positional arguments followed by
    # key/value mappings. Parsing keyword arguments from the end until we hit
    # something that isn't a key/value mapping. The rest are positional.
    
    while fields:
      kw_match = KW_ARG.match(fields[-1])
      
      if kw_match:
        k, v = kw_match.groups()
        self.keyword_args[k] = v
        fields.pop() # remove the field
      else:
        # not a key/value mapping, the remaining fields are positional
        self.positional_args = fields
        break
    
    # Setting attributes for the fields that we recognize. Unrecognized fields
    # only appear in our 'positional_args' and 'keyword_args' attributes.
    
    for i in xrange(len(self._POSITIONAL_ARGS)):
      attr_name = self._POSITIONAL_ARGS[i]
      attr_value = None
      
      if self.positional_args:
        if attr_name in self._QUOTED:
          attr_values = [self.positional_args.pop(0)]
          
          if not attr_values[0].startswith('"'):
            raise stem.ProtocolError("The %s value should be quoted, but didn't have a starting quote: %s" % self)
          
          while True:
            if not self.positional_args:
              raise stem.ProtocolError("The %s value should be quoted, but didn't have an ending quote: %s" % self)
            
            attr_values.append(self.positional_args.pop(0))
            if attr_values[-1].endswith('"'): break
          
          attr_value = " ".join(attr_values)[1:-1]
        else:
          attr_value = self.positional_args.pop(0)
      
      setattr(self, attr_name, attr_value)
    
    for controller_attr_name, attr_name in self._KEYWORD_ARGS.items():
      setattr(self, attr_name, self.keyword_args.get(controller_attr_name))
  
  # method overwritten by our subclasses for special handling that they do
  def _parse(self):
    pass

class AddrMapEvent(Event):
  """
  Event that indicates a new address mapping.
  
  :var str hostname: address being resolved
  :var str destination: destionation of the resolution, this is usually an ip,
    but could be a hostname if TrackHostExits is enabled or **NONE** if the
    resolution failed
  :var datetime expiry: expiration time of the resolution in local time
  :var str error: error code if the resolution failed
  :var datetime utc_expiry: expiration time of the resolution in UTC
  """
  
  # TODO: The spec for this event is a little vague. Making a couple guesses
  # about it...
  #
  # https://trac.torproject.org/7515
  
  _POSITIONAL_ARGS = ("hostname", "destination", "expiry")
  _KEYWORD_ARGS = {
    "error": "error",
    "EXPIRES": "utc_expiry",
  }
  _QUOTED = ("expiry", "EXPIRES")
  
  def _parse(self):
    if self.destination == "<error>":
      self.destination = None
    
    if self.expiry != None:
      self.expiry = datetime.datetime.strptime(self.expiry, "%Y-%m-%d %H:%M:%S")
    
    if self.utc_expiry != None:
      self.utc_expiry = datetime.datetime.strptime(self.utc_expiry, "%Y-%m-%d %H:%M:%S")

class AuthDirNewDescEvent(Event):
  """
  Event specific to directory authorities, indicating that we just received new
  descriptors. The descriptor type contained within this event is unspecified
  so the descriptor contents are left unparsed.
  
  :var stem.AuthDescriptorAction action: what is being done with the descriptor
  :var str message: explanation of why we chose this action
  :var str descriptor: content of the descriptor
  """
  
  _SKIP_PARSING = True
  
  def _parse(self):
    lines = str(self).split('\n')
    
    if len(lines) < 5:
      raise stem.ProtocolError("AUTHDIR_NEWDESCS events must contain lines for at least the type, action, message, descriptor, and terminating 'OK'")
    elif not lines[-1] == "OK":
      raise stem.ProtocolError("AUTHDIR_NEWDESCS doesn't end with an 'OK'")
    
    self.action = lines[1]
    self.message = lines[2]
    self.descriptor = '\n'.join(lines[3:-1])

class BandwidthEvent(Event):
  """
  Event emitted every second with the bytes sent and received by tor.
  
  :var long read: bytes received by tor that second
  :var long written: bytes sent by tor that second
  """
  
  _POSITIONAL_ARGS = ("read", "written")
  
  def _parse(self):
    if not self.read:
      raise stem.ProtocolError("BW event is missing its read value")
    elif not self.written:
      raise stem.ProtocolError("BW event is missing its written value")
    elif not self.read.isdigit() or not self.written.isdigit():
      raise stem.ProtocolError("A BW event's bytes sent and received should be a positive numeric value, received: %s" % self)
    
    self.read = long(self.read)
    self.written = long(self.written)

class CircuitEvent(Event):
  """
  Event that indicates that a circuit has changed.
  
  The fingerprint or nickname values in our 'path' may be **None** if the
  VERBOSE_NAMES feature isn't enabled. The option was first introduced in tor
  version 0.1.2.2, and on by default after 0.2.2.1.
  
  :var str id: circuit identifier
  :var stem.CircStatus status: reported status for the circuit
  :var tuple path: relays involved in the circuit, these are
    **(fingerprint, nickname)** tuples
  :var tuple build_flags: :data:`~stem.CircBuildFlag` attributes
    governing how the circuit is built
  :var stem.CircPurpose purpose: purpose that the circuit is intended for
  :var stem.HiddenServiceState hs_state: status if this is a hidden service circuit
  :var str rend_query: circuit's rendezvous-point if this is hidden service related
  :var datetime created: time when the circuit was created or cannibalized
  :var stem.CircClosureReason reason: reason for the circuit to be closed
  :var stem.CircClosureReason remote_reason: remote side's reason for the circuit to be closed
  """
  
  _POSITIONAL_ARGS = ("id", "status", "path")
  _KEYWORD_ARGS = {
    "BUILD_FLAGS": "build_flags",
    "PURPOSE": "purpose",
    "HS_STATE": "hs_state",
    "REND_QUERY": "rend_query",
    "TIME_CREATED": "created",
    "REASON": "reason",
    "REMOTE_REASON": "remote_reason",
  }
  
  def _parse(self):
    self.path = tuple(stem.control._parse_circ_path(self.path))
    
    if self.build_flags != None:
      self.build_flags = tuple(self.build_flags.split(','))
    
    if self.created != None:
      try:
        self.created = str_tools.parse_iso_timestamp(self.created)
      except ValueError, exc:
        raise stem.ProtocolError("Unable to parse create date (%s): %s" % (exc, self))
    
    if self.id != None and not tor_tools.is_valid_circuit_id(self.id):
      raise stem.ProtocolError("Circuit IDs must be one to sixteen alphanumeric characters, got '%s': %s" % (self.id, self))
    
    # log if we have an unrecognized status, build flag, purpose, hidden
    # service state, or closure reason
    
    unrecognized_msg = UNRECOGNIZED_ATTR_MSG % ("CIRC", self)
    
    if self.status and (not self.status in stem.CircStatus):
      log_id = "event.circ.unknown_status.%s" % self.status
      log.log_once(log_id, log.INFO, unrecognized_msg % ('status', self.status))
    
    if self.build_flags:
      for flag in self.build_flags:
        if not flag in stem.CircBuildFlag:
          log_id = "event.circ.unknown_build_flag.%s" % flag
          log.log_once(log_id, log.INFO, unrecognized_msg % ('build flag', flag))
    
    if self.purpose and (not self.purpose in stem.CircPurpose):
      log_id = "event.circ.unknown_purpose.%s" % self.purpose
      log.log_once(log_id, log.INFO, unrecognized_msg % ('purpose', self.purpose))
    
    if self.hs_state and (not self.hs_state in stem.HiddenServiceState):
      log_id = "event.circ.unknown_hs_state.%s" % self.hs_state
      log.log_once(log_id, log.INFO, unrecognized_msg % ('hidden service state', self.hs_state))
    
    if self.reason and (not self.reason in stem.CircClosureReason):
      log_id = "event.circ.unknown_reason.%s" % self.reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('reason', self.reason))
    
    if self.remote_reason and (not self.remote_reason in stem.CircClosureReason):
      log_id = "event.circ.unknown_remote_reason.%s" % self.remote_reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('remote reason', self.remote_reason))

class DescChangedEvent(Event):
  """
  Event that indicates that our descriptor has changed. This was first added in
  tor version 0.1.2.2.
  """
  
  pass

class GuardEvent(Event):
  """
  Event that indicates that our guard relays have changed.
  
  :var stem.GuardType guard_type: purpose the guard relay is for
  :var str name: nickname or fingerprint of the guard relay
  :var stem.GuardStatus status: status of the guard relay
  """
  
  # TODO: We should replace the 'name' field with a fingerprint or nickname
  # attribute once we know what it can be...
  #
  # https://trac.torproject.org/7619
  
  _POSITIONAL_ARGS = ("guard_type", "name", "status")

class LogEvent(Event):
  """
  Tor logging event. These are the most visible kind of event since, by
  default, tor logs at the NOTICE :data:`~stem.Runlevel` to stdout.
  
  :var stem.Runlevel runlevel: runlevel of the logged message
  :var str message: logged message
  """
  
  _SKIP_PARSING = True
  
  def _parse(self):
    self.runlevel = self.type
    
    # message is our content, minus the runlevel and ending "OK" if a
    # multi-line message
    
    self.message = str(self)[len(self.runlevel) + 1:].rstrip("\nOK")
    
    # log if our runlevel isn't recognized
    
    unrecognized_msg = UNRECOGNIZED_ATTR_MSG % ("Logging", self)
    
    if not self.runlevel in stem.Runlevel:
      log_id = "event.logging.unknown_runlevel.%s" % self.runlevel
      log.log_once(log_id, log.INFO, unrecognized_msg % ('runlevel', self.runlevel))

class NetworkStatusEvent(Event):
  """
  Event for when our copy of the consensus has changed. This was introduced in
  tor version 0.1.2.3.
  
  :param list desc: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` for the changed descriptors
  """
  
  _SKIP_PARSING = True
  
  def _parse(self):
    content = str(self).lstrip("NS\n")
    
    self.desc = list(stem.descriptor.router_status_entry.parse_file(
      StringIO.StringIO(content),
      True,
      entry_class = stem.descriptor.router_status_entry.RouterStatusEntryV3,
    ))

class NewDescEvent(Event):
  """
  Event that indicates that a new descriptor is available.
  
  The fingerprint or nickname values in our 'relays' may be **None** if the
  VERBOSE_NAMES feature isn't enabled. The option was first introduced in tor
  version 0.1.2.2, and on by default after 0.2.2.1.
  
  :param tuple relays: **(fingerprint, nickname)** tuples for the relays with
    new descriptors
  """
  
  def _parse(self):
    self.relays = tuple([stem.control._parse_circ_entry(entry) for entry in str(self).split()[1:]])

class ORConnEvent(Event):
  """
  Event that indicates a change in a relay connection. The 'endpoint' could be
  any of several things including a...
  
  * fingerprint
  * nickname
  * 'fingerprint=nickname' pair
  * address:port
  
  The derived 'endpoint_*' attributes are generally more useful.
  
  :var str endpoint: relay that the event concerns
  :var str endpoint_fingerprint: endpoint's finterprint if it was provided
  :var str endpoint_nickname: endpoint's nickname if it was provided
  :var str endpoint_address: endpoint's address if it was provided
  :var int endpoint_port: endpoint's port if it was provided
  :var stem.ORStatus status: state of the connection
  :var stem.ORClosureReason reason: reason for the connection to be closed
  :var int circ_count: number of established and pending circuits
  """
  
  _POSITIONAL_ARGS = ("endpoint", "status")
  _KEYWORD_ARGS = {
    "REASON": "reason",
    "NCIRCS": "circ_count",
  }
  
  def _parse(self):
    self.endpoint_fingerprint = None
    self.endpoint_nickname = None
    self.endpoint_address = None
    self.endpoint_port = None
    
    try:
      self.endpoint_fingerprint, self.endpoint_nickname = \
        stem.control._parse_circ_entry(self.endpoint)
    except stem.ProtocolError:
      if not ':' in self.endpoint:
        raise stem.ProtocolError("ORCONN endpoint is neither a relay nor 'address:port': %s" % self)
      
      address, port = self.endpoint.split(':', 1)
      
      if not connection.is_valid_port(port):
        raise stem.ProtocolError("ORCONN's endpoint location's port is invalid: %s" % self)
      
      self.endpoint_address = address
      self.endpoint_port = int(port)
    
    if self.circ_count != None:
      if not self.circ_count.isdigit():
        raise stem.ProtocolError("ORCONN event got a non-numeric circuit count (%s): %s" % (self.circ_count, self))
      
      self.circ_count = int(self.circ_count)
    
    # log if we have an unrecognized status or reason
    
    unrecognized_msg = UNRECOGNIZED_ATTR_MSG % ("ORCONN", self)
    
    if self.status and (not self.status in stem.ORStatus):
      log_id = "event.orconn.unknown_status.%s" % self.status
      log.log_once(log_id, log.INFO, unrecognized_msg % ('status', self.status))
    
    if self.reason and (not self.reason in stem.ORClosureReason):
      log_id = "event.orconn.unknown_reason.%s" % self.reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('reason', self.reason))

class StatusEvent(Event):
  """
  Notification of a change in tor's state. These are generally triggered for
  the same sort of things as log messages of the NOTICE level or higher.
  However, unlike :class:`~stem.response.events.LogEvent` these contain well
  formed data.
  
  :var stem.StatusType status_type: category of the status event
  :var stem.Runlevel runlevel: runlevel of the logged message
  :var str message: logged message
  """
  
  _POSITIONAL_ARGS = ("runlevel", "action")
  _PERMISSIVE_QUOTED_MAPPINGS = True
  
  def _parse(self):
    if self.type == 'STATUS_GENERAL':
      self.status_type = stem.StatusType.GENERAL
    elif self.type == 'STATUS_CLIENT':
      self.status_type = stem.StatusType.CLIENT
    elif self.type == 'STATUS_SERVER':
      self.status_type = stem.StatusType.SERVER
    else:
      raise ValueError("BUG: Unrecognized status type (%s), likely an EVENT_TYPE_TO_CLASS addition without revising how 'status_type' is assigned." % self.type)
    
    # log if our runlevel isn't recognized
    
    unrecognized_msg = UNRECOGNIZED_ATTR_MSG % ("Status", self)
    
    if not self.runlevel in stem.Runlevel:
      log_id = "event.status.unknown_runlevel.%s" % self.runlevel
      log.log_once(log_id, log.INFO, unrecognized_msg % ('runlevel', self.runlevel))

class StreamEvent(Event):
  """
  Event that indicates that a stream has changed.
  
  :var str id: stream identifier
  :var stem.StreamStatus status: reported status for the stream
  :var str circ_id: circuit that the stream is attached to
  :var str target: destination of the stream
  :var str target_address: destination address (ip or hostname)
  :var int target_port: destination port
  :var stem.StreamClosureReason reason: reason for the stream to be closed
  :var stem.StreamClosureReason remote_reason: remote side's reason for the stream to be closed
  :var stem.StreamSource source: origin of the REMAP request
  :var str source_addr: requester of the connection
  :var str source_address: requester address (ip or hostname)
  :var int source_port: requester port
  :var stem.StreamPurpose purpose: purpose for the stream
  """
  
  _POSITIONAL_ARGS = ("id", "status", "circ_id", "target")
  _KEYWORD_ARGS = {
    "REASON": "reason",
    "REMOTE_REASON": "remote_reason",
    "SOURCE": "source",
    "SOURCE_ADDR": "source_addr",
    "PURPOSE": "purpose",
  }
  
  def _parse(self):
    if self.target is None:
      self.target_address = None
      self.target_port = None
    else:
      if not ':' in self.target:
        raise stem.ProtocolError("Target location must be of the form 'address:port': %s" % self)
      
      address, port = self.target.split(':', 1)
      
      if not connection.is_valid_port(port, allow_zero = True):
        raise stem.ProtocolError("Target location's port is invalid: %s" % self)
      
      self.target_address = address
      self.target_port = int(port)
    
    if self.source_addr is None:
      self.source_address = None
      self.source_port = None
    else:
      if not ':' in self.source_addr:
        raise stem.ProtocolError("Source location must be of the form 'address:port': %s" % self)
      
      address, port = self.source_addr.split(':', 1)
      
      if not connection.is_valid_port(port, allow_zero = True):
        raise stem.ProtocolError("Source location's port is invalid: %s" % self)
      
      self.source_address = address
      self.source_port = int(port)
    
    # spec specifies a circ_id of zero if the stream is unattached
    
    if self.circ_id == "0":
      self.circ_id = None
    
    # log if we have an unrecognized closure reason or purpose
    
    unrecognized_msg = UNRECOGNIZED_ATTR_MSG % ("STREAM", self)
    
    if self.reason and (not self.reason in stem.StreamClosureReason):
      log_id = "event.stream.reason.%s" % self.reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('reason', self.reason))
    
    if self.remote_reason and (not self.remote_reason in stem.StreamClosureReason):
      log_id = "event.stream.remote_reason.%s" % self.remote_reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('remote reason', self.remote_reason))
    
    if self.purpose and (not self.purpose in stem.StreamPurpose):
      log_id = "event.stream.purpose.%s" % self.purpose
      log.log_once(log_id, log.INFO, unrecognized_msg % ('purpose', self.purpose))

EVENT_TYPE_TO_CLASS = {
  "ADDRMAP": AddrMapEvent,
  "AUTHDIR_NEWDESCS": AuthDirNewDescEvent,
  "BW": BandwidthEvent,
  "CIRC": CircuitEvent,
  "DEBUG": LogEvent,
  "DESCCHANGED": DescChangedEvent,
  "ERR": LogEvent,
  "GUARD": GuardEvent,
  "INFO": LogEvent,
  "NEWDESC": NewDescEvent,
  "NOTICE": LogEvent,
  "NS": NetworkStatusEvent,
  "ORCONN": ORConnEvent,
  "STATUS_CLIENT": StatusEvent,
  "STATUS_GENERAL": StatusEvent,
  "STATUS_SERVER": StatusEvent,
  "STREAM": StreamEvent,
  "WARN": LogEvent,
  
  # accounting for a bug in tor 0.2.0.22
  "STATUS_SEVER": StatusEvent,
}

