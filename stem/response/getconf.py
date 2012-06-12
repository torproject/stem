import stem.socket
import stem.response

def _split_line(line):
  if line.is_next_mapping(quoted = False):
    return line.split("=", 1) # TODO: make this part of the ControlLine?
  elif line.is_next_mapping(quoted = True):
    return line.pop_mapping(True).items()[0]
  else:
    return (line.pop(), None)

class GetConfResponse(stem.response.ControlMessage):
  """
  Reply for a GETCONF query.
  
  :var dict entries:
    mapping between the queried options (string) and their values (string/list
    of strings)
  """
  
  def _parse_message(self):
    # Example:
    # 250-CookieAuthentication=0
    # 250-ControlPort=9100
    # 250-DataDirectory=/home/neena/.tor
    # 250 DirPort
    
    self.entries = {}
    remaining_lines = list(self)

    if self.content() == [("250", " ", "OK")]: return
    
    if not self.is_ok():
      unrecognized_keywords = []
      for code, _, line in self.content():
        if code == '552' and line.startswith("Unrecognized configuration key \"") and line.endswith("\""):
          unrecognized_keywords.append(line[32:-1])

      if unrecognized_keywords:
        raise stem.socket.InvalidArguments("GETCONF request contained unrecognized keywords: %s\n" \
            % ', '.join(unrecognized_keywords), unrecognized_keywords)
      else:
        raise stem.socket.ProtocolError("GETCONF response contained a non-OK status code:\n%s" % self)
    
    while remaining_lines:
      line = remaining_lines.pop(0)

      key, value = _split_line(line)
      entry = self.entries.get(key, None)

      if type(entry) == str and entry != value:
        self.entries[key] = [entry]
        self.entries[key].append(value)
      elif type(entry) == list and not value in entry:
        self.entries[key].append(value)
      else:
        self.entries[key] = value

