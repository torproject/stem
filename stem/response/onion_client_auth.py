# Copyright 2015-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.response
from stem.util import log


class OnionClientAuthAddResponse(stem.response.ControlMessage):
  """
  ONION_CLIENT_AUTH_ADD response.
  """

  def _parse_message(self) -> None:
    # ONION_CLIENT_AUTH_ADD responds with:
    # '250 OK',
    # '251 Client for onion existed and replaced',
    # '252 Registered client and decrypted desc',
    # '512 Invalid v3 address [service id]',
    # '553 Unable to store creds for [service id]'

    if not self.is_ok():
      raise stem.ProtocolError("ONION_CLIENT_AUTH_ADD response didn't have an OK status: %s" % self)


class OnionClientAuthRemoveResponse(stem.response.ControlMessage):
  """
  ONION_CLIENT_AUTH_REMOVE response.
  """

  def _parse_message(self) -> None:
    # ONION_CLIENT_AUTH_REMOVE responds with:
    # '250 OK',
    # '251 No credentials for [service id]',
    # '512 Invalid v3 address [service id]'

    if not self.is_ok():
      raise stem.ProtocolError("ONION_CLIENT_AUTH_REMOVE response didn't have an OK status: %s" % self)


class OnionClientAuthViewResponse(stem.response.ControlMessage):
  """
  ONION_CLIENT_AUTH_VIEW response.
  """

  def _parse_message(self) -> None:
    # ONION_CLIENT_AUTH_VIEW responds with:
    # '250 OK' if there was Client Auth for this service or if the service is a valid address,
    # ''512 Invalid v3 address [service id]'

    self.client_auth_credential = None

    if not self.is_ok():
      raise stem.ProtocolError("ONION_CLIENT_AUTH_VIEW response didn't have an OK status: %s" % self)
    else:
      for line in list(self):
        if line.startswith('CLIENT'):
          key, value = line.split(' ', 1)
          log.debug(key)
          log.debug(value)

          self.client_auth_credential = value
