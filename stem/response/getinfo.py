import stem.socket

class GetInfoResponse(stem.socket.ControlMessage):
  """
  Reply for a GETINFO query.
  
  Attributes:
    values (dict) - mapping between the queried options and their values
  """
  
  def _parse_message(self):
    # Example:
    # 250-version=0.2.3.11-alpha-dev (git-ef0bc7f8f26a917c)
    # 250+config-text=
    # ControlPort 9051
    # DataDirectory /home/atagar/.tor
    # ExitPolicy reject *:*
    # Log notice stdout
    # Nickname Unnamed
    # ORPort 9050
    # .
    # 250 OK
    
    self.values = {}
    
    for line in self:
      if line == "OK": break
      elif not "=" in line:
        raise stem.socket.ProtocolError("GETINFO replies should only contain parameter=value mappings: %s" % line)
      
      key, value = line.split("=", 1)
      
      # if the value is a multiline value then it *must* be of the form
      # '<key>=\n<value>'
      
      if "\n" in value:
        if value.startswith("\n"):
          value = value[1:]
        else:
          raise stem.socket.ProtocolError("GETINFO response contained a multiline value that didn't start with a newline: %s" % line)
      
      self.values[key] = value

