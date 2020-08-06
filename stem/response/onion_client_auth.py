# Copyright 2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import stem.control
import stem.response


class OnionClientAuthViewResponse(stem.response.ControlMessage):
  """
  ONION_CLIENT_AUTH_VIEW response.

  :var str requested: queried hidden service id, this is None if all
    credentials were requested
  :var dict credentials: mapping of hidden service ids to their
    :class:`~stem.control.HiddenServiceCredential`
  """

  def _parse_message(self) -> None:
    # Example:
    #   250-ONION_CLIENT_AUTH_VIEW yvhz3ofkv7gwf5hpzqvhonpr3gbax2cc7dee3xcnt7dmtlx2gu7vyvid
    #   250-CLIENT yvhz3ofkv7gwf5hpzqvhonpr3gbax2cc7dee3xcnt7dmtlx2gu7vyvid x25519:FCV0c0ELDKKDpSFgVIB8Yow8Evj5iD+GoiTtK878NkQ=
    #   250 OK

    self.requested = None
    self.credentials = {}

    if not self.is_ok():
      raise stem.ProtocolError("ONION_CLIENT_AUTH_VIEW response didn't have an OK status: %s" % self)

    # first line optionally contains the service id this request was for

    first_line = list(self)[0]

    if not first_line.startswith('ONION_CLIENT_AUTH_VIEW'):
      raise stem.ProtocolError("Response should begin with 'ONION_CLIENT_AUTH_VIEW': %s" % self)
    elif ' ' in first_line:
      self.requested = first_line.split(' ')[1]

    for credential_line in list(self)[1:-1]:
      attributes = credential_line.split(' ')

      if len(attributes) < 3:
        raise stem.ProtocolError('ONION_CLIENT_AUTH_VIEW lines must contain an address and credential: %s' % self)
      elif attributes[0] != 'CLIENT':
        raise stem.ProtocolError("ONION_CLIENT_AUTH_VIEW lines should begin with 'CLIENT': %s" % self)
      elif ':' not in attributes[2]:
        raise stem.ProtocolError("ONION_CLIENT_AUTH_VIEW credentials must be of the form 'encryption_type:key': %s" % self)

      service_id = attributes[1]
      key_type, private_key = attributes[2].split(':', 1)
      client_name = None
      flags = []

      for attr in attributes[2:]:
        if '=' not in attr:
          raise stem.ProtocolError("'%s' expected to be a 'key=value' mapping: %s" % (attr, self))

        key, value = attr.split('=', 1)

        if key == 'ClientName':
          client_name = value
        elif key == 'Flags':
          flags = value.split(',')

      self.credentials[service_id] = stem.control.HiddenServiceCredential(service_id, private_key, key_type, client_name, flags)
