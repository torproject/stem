import socks  # SocksiPy module
import socket
import urllib

SOCKS_PORT = 7000

# Set socks proxy and wrap the urllib module

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
socket.socket = socks.socksocket

# Perform DNS resolution through the socket

def getaddrinfo(*args):
  return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

socket.getaddrinfo = getaddrinfo

def query(url):
  """
  Uses urllib to fetch a site using SocksiPy for Tor over the SOCKS_PORT.
  """

  try:
    return urllib.urlopen(url).read()
  except:
    return "Unable to reach %s" % url
