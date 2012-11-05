import re

import stem.response
import stem.socket

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
      raise stem.socket.ProtocolError("Received a blank tor event. Events must at the very least have a type.")
    
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

class BandwidthEvent(Event):
  """
  Event emitted every second with the bytes sent and received by tor.
  
  :var long read: bytes received by tor that second
  :var long written: bytes sent by tor that second
  """
  
  _POSITIONAL_ARGS = ("read", "written")
  
  def _parse(self):
    if not self.read:
      raise stem.socket.ProtocolError("BW event is missing its read value")
    elif not self.written:
      raise stem.socket.ProtocolError("BW event is missing its written value")
    elif not self.read.isdigit() or not self.written.isdigit():
      raise stem.socket.ProtocolError("A BW event's bytes sent and received should be a positive numeric value, received: %s" % self)
    
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
  "BW": BandwidthEvent,
  "DEBUG": LogEvent,
  "INFO": LogEvent,
  "NOTICE": LogEvent,
  "WARN": LogEvent,
  "ERR": LogEvent,
}

