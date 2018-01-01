# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for interacting with the ORPort provided by Tor relays. The
:class:`~stem.client.Relay` is a wrapper for :class:`~stem.socket.RelaySocket`,
providing higher level functions in much the same way as our
:class:`~stem.control.Controller` wraps :class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

**Module Overview:**

::

  Relay - Connection with a relay's ORPort.
"""


class Relay(object):
  """
  Connection with a `Tor relay's ORPort
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_.
  """
