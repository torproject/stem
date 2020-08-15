# Copyright 2012-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response
import stem.socket


class MapAddressResponse(stem.response.ControlMessage):
  """
  MAPADDRESS reply. Responses can contain a mixture of successes and failures,
  such as...

  ::

    512-syntax error: invalid address '@@@'
    250 1.2.3.4=tor.freehaven.net

  This only raises an exception if **every** mapping fails. Otherwise
  **mapped** enumerates our successes and **failures** lists any
  failure messages.

  :var dict mapped: mapping between the original and replacement addresses
  :var list failures: failure listed within this reply

  :raises:
    * :class:`stem.OperationFailed` if Tor was unable to satisfy the request
    * :class:`stem.InvalidRequest` if the addresses provided were invalid
  """

  def _parse_message(self) -> None:
    if not self.is_ok():
      for code, _, message in self.content():
        if code == '512':
          raise stem.InvalidRequest(code, message)
        elif code == '451':
          raise stem.OperationFailed(code, message)
        else:
          raise stem.ProtocolError('MAPADDRESS returned unexpected response code: %s', code)

    self.mapped = {}
    self.failures = []

    for code, _, message in self.content():
      if code == '250':
        try:
          key, value = message.split('=', 1)
          self.mapped[key] = value
        except ValueError:
          raise stem.ProtocolError(None, "MAPADDRESS returned '%s', which isn't a mapping" % message)
      else:
        self.failures.append(message)
