import re

import stem.socket
import stem.response

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
        if code == '552':
          try:
            # to parse: 552 Unrecognized configuration key "zinc"
            unrecognized_keywords.append(re.search('"([^"]+)"', line).groups()[0])
          except:
            pass

      if unrecognized_keywords:
        raise stem.socket.InvalidRequest("GETCONF request contained unrecognized keywords: %s\n" \
            % ', '.join(unrecognized_keywords))
      else:
        raise stem.socket.ProtocolError("GETCONF response contained a non-OK status code:\n%s" % self)
    
    while remaining_lines:
      line = remaining_lines.pop(0)

      if '=' in line:
        if line[line.find("=") + 1] == "\"":
          key, value = line.pop_mapping(True)
        else:
          key, value = line.split("=", 1)
      else:
        key, value = (line, None)
      
      self.entries[key] = value

