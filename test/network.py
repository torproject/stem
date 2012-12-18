"""
Helper functions and classes to support tests which need to connect through
the tor network.

::

  ProxyError - Base error for proxy issues.
    +- SocksError - Reports problems returned by the SOCKS proxy.
"""

class ProxyError(Exception):
  """ Base error for proxy issues. """

class SocksError(ProxyError):
  """
  Exception raised for any problems returned by the SOCKS proxy.
  
  :var int code: error code returned by the SOCKS proxy
  """
  
  # Error messages copied from http://en.wikipedia.org/wiki/SOCKS,
  # retrieved 2012-12-15 17:09:21.
  _ERROR_MESSAGE = {
    0x01: "general failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused by destination host",
    0x06: "TTL expired",
    0x07: "command not supported / protocol error",
    0x08: "address type not supported",
  }
  
  def __init__(self, code):
    self.code = code
  
  def __str__(self):
    code = 0x01
    if self.code in self._ERROR_MESSAGE:
      code = self.code
    return "[%s] %s" % (code, self._ERROR_MESSAGE[code])
