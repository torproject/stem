
import re
import binascii

import stem.socket
import stem.response

class AuthChallengeResponse(stem.response.ControlMessage):
  """
  AUTHCHALLENGE query response.
  
  :var str server_hash: server hash returned by Tor
  :var str server_nonce: server nonce returned by Tor
  """
  
  def _parse_message(self):
    # Example:
    #   250 AUTHCHALLENGE SERVERHASH=680A73C9836C4F557314EA1C4EDE54C285DB9DC89C83627401AEF9D7D27A95D5 SERVERNONCE=F8EA4B1F2C8B40EF1AF68860171605B910E3BBCABADF6FC3DB1FA064F4690E85
    
    _ProtocolError = stem.socket.ProtocolError

    try:
      line = self[0]
    except IndexError:
      raise _ProtocolError("Received empty AUTHCHALLENGE response")

    # sanity check that we're a AUTHCHALLENGE response
    if not line.pop() == "AUTHCHALLENGE":
      raise _ProtocolError("Message is not an AUTHCHALLENGE response (%s)" % self)

    if len(self) > 1:
      raise _ProtocolError("Received multiline AUTHCHALLENGE response (%s)" % line)

    self.server_hash, self.server_nonce = None, None

    try:
      key, value = line.pop_mapping()
    except (IndexError, ValueError), exc:
      raise _ProtocolError(exc.message)
    if key == "SERVERHASH":
      if not re.match("^[A-Fa-f0-9]{64}$", value):
        raise _ProtocolError("SERVERHASH has an invalid value: %s" % value)
          
      self.server_hash = binascii.a2b_hex(value)

    try:
      key, value = line.pop_mapping()
    except (IndexError, ValueError), exc:
      raise _ProtocolError(exc.message)
    if key == "SERVERNONCE":
      if not re.match("^[A-Fa-f0-9]{64}$", value):
        raise _ProtocolError("SERVERNONCE has an invalid value: %s" % value)
      
      self.server_nonce = binascii.a2b_hex(value)
      
    msg = ""
    if not self.server_hash:
      msg.append("SERVERHASH")
      if not self.server_nonce:
        msg.append("and SERVERNONCE")
    else:
      if not self.server_nonce:
        msg.append("SERVERNONCE")

    if msg:
      raise _ProtocolError("AUTHCHALLENGE response is missing %s." % msg)

