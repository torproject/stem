import stem.socket
import stem.response

def _getval(dictionary, key):
  try:
    return dictionary[key]
  except KeyError:
    pass

def _split_line(line):
  try:
    if '=' in line:
      if line[line.find("=") + 1] == "\"":
        return line.pop_mapping(True)
      else:
        return line.split("=", 1)
    else:
      return (line, None)
  except IndexError:
    return (line[:-1], None)

class GetConfResponse(stem.response.ControlMessage):
  """
  Reply for a GETCONF query.
  
  :var dict entries: mapping between the queried options and their values
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
      entry = _getval(self.entries, key)

      if type(entry) == str and entry != value:
        self.entries[key] = [entry]
        self.entries[key].append(value)
      elif type(entry) == list and not value in entry:
        self.entries[key].append(value)
      else:
        self.entries[key] = value

