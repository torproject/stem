import re

import stem.control
import stem.response

from stem.util import log, str_tools, tor_tools

# Matches keyword=value arguments. This can't be a simple "(.*)=(.*)" pattern
# because some positional arguments, like circuit paths, can have an equal
# sign.

KW_ARG = re.compile("([A-Za-z0-9_]+)=(.*)")

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
  
  def _parse_message(self, arrived_at):
    fields = str(self).split()
    
    if not fields:
      raise stem.ProtocolError("Received a blank tor event. Events must at the very least have a type.")
    
    self.type = fields.pop(0)
    self.arrived_at = arrived_at
    
    # if we're a recognized event type then translate ourselves into that subclass
    
    if self.type in EVENT_TYPE_TO_CLASS:
      self.__class__ = EVENT_TYPE_TO_CLASS[self.type]
    
    # Tor events contain some number of positional arguments followed by
    # key/value mappings. Parsing keyword arguments from the end until we hit
    # something that isn't a key/value mapping. The rest are positional.
    
    self.positional_args = []
    self.keyword_args = {}
    
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
      attr_value = self.positional_args[i] if i < len(self.positional_args) else None
      
      setattr(self, attr_name, attr_value)
    
    for controller_attr_name, attr_name in self._KEYWORD_ARGS.items():
      setattr(self, attr_name, self.keyword_args.get(controller_attr_name))
    
    self._parse()
  
  # method overwritten by our subclasses for special handling that they do
  def _parse(self):
    pass

class CircuitEvent(Event):
  """
  Event that indicates that a circuit has changed.
  
  The fingerprint or nickname values in our path may be **None** if the
  VERBOSE_NAMES feature is unavailable. The option was first introduced in tor
  version 0.1.2.2.
  
  :var str id: circuit identifier
  :var stem.control.CircStatus status: reported status for the circuit
  :var tuple path: relays involved in the circuit, these are
    **(fingerprint, nickname)** tuples
  :var tuple build_flags: :data:`~stem.control.CircBuildFlag` attributes
    governing how the circuit is built
  :var stem.control.CircPurpose purpose: purpose that the circuit is intended for
  :var stem.control.HiddenServiceState hs_state: status if this is a hidden service circuit
  :var str rend_query: circuit's rendezvous-point if this is hidden service related
  :var datetime created: time when the circuit was created or cannibalized
  :var stem.control.CircClosureReason reason: reason for the circuit to be closed
  :var stem.control.CircClosureReason remote_reason: remote side's reason for the circuit to be closed
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
    
    unrecognized_msg = "CIRC event had an unrecognised %%s (%%s). Maybe a new addition to the control protocol? Full Event: '%s'" % self
    
    if self.status and (not self.status in stem.control.CircStatus):
      log_id = "event.circ.unknown_status.%s" % self.status
      log.log_once(log_id, log.INFO, unrecognized_msg % ('status', self.status))
    
    if self.build_flags:
      for flag in self.build_flags:
        if not flag in stem.control.CircBuildFlag:
          log_id = "event.circ.unknown_build_flag.%s" % flag
          log.log_once(log_id, log.INFO, unrecognized_msg % ('build flag', flag))
    
    if self.purpose and (not self.purpose in stem.control.CircPurpose):
      log_id = "event.circ.unknown_purpose.%s" % self.purpose
      log.log_once(log_id, log.INFO, unrecognized_msg % ('purpose', self.purpose))
    
    if self.hs_state and (not self.hs_state in stem.control.HiddenServiceState):
      log_id = "event.circ.unknown_hs_state.%s" % self.hs_state
      log.log_once(log_id, log.INFO, unrecognized_msg % ('hidden service state', self.hs_state))
    
    if self.reason and (not self.reason in stem.control.CircClosureReason):
      log_id = "event.circ.unknown_reason.%s" % self.reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('reason', self.reason))
    
    if self.remote_reason and (not self.remote_reason in stem.control.CircClosureReason):
      log_id = "event.circ.unknown_remote_reason.%s" % self.remote_reason
      log.log_once(log_id, log.INFO, unrecognized_msg % ('remote reason', self.remote_reason))

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

class LogEvent(Event):
  """
  Tor logging event. These are the most visible kind of event since, by
  default, tor logs at the NOTICE runlevel to stdout.
  
  :var str runlevel: runlevel of the logged message
  :var str message: logged message
  """
  
  def _parse(self):
    self.runlevel = self.type
    
    # message is our content, minus the runlevel and ending "OK" if a
    # multi-line message
    
    self.message = str(self)[len(self.runlevel) + 1:].rstrip("\nOK")

EVENT_TYPE_TO_CLASS = {
  "CIRC": CircuitEvent,
  "BW": BandwidthEvent,
  "DEBUG": LogEvent,
  "INFO": LogEvent,
  "NOTICE": LogEvent,
  "WARN": LogEvent,
  "ERR": LogEvent,
}

