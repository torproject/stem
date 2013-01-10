import socket
import struct

from stem import ProtocolError, SocketError

error_msgs = {
  0x5a: "SOCKS4A request granted",
  0x5b: "SOCKS4A request rejected or failed",
  0x5c: "SOCKS4A request failed because client is not running identd (or not reachable from the server)",
  0x5d: "SOCKS4A request failed because client's identd could not confirm the user ID string in the request",
}

ip_request = """GET /ip HTTP/1.0
Host: ifconfig.me
Accept-Encoding: identity

"""


def external_ip(host, port):
  """
  Returns the externally visible IP address when using a SOCKS4a proxy.
  Negotiates the socks connection, connects to ipconfig.me and requests
  http://ifconfig.me/ip to find out the externally visible IP.

  Supports only SOCKS4a proxies.

  :param str host: hostname/IP of the proxy server
  :param int port: port on which the proxy server is listening

  :returns: externally visible IP address, or None if it isn't able to

  :raises: :class:`stem.socket.SocketError`: unable to connect a socket to the socks server
  """

  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, int(port)))
  except Exception, exc:
    raise SocketError("Failed to connect to the socks server: " + str(exc))

  try:
    negotiate_socks(sock, "ifconfig.me", 80)
    sock.sendall(ip_request)
    response = sock.recv(1000)

    # everything after the blank line is the 'data' in a HTTP response
    # The response data for our request for request should be an IP address + '\n'
    return response[response.find("\r\n\r\n"):].strip()
  except Exception, exc:
    return None


def negotiate_socks(sock, host, port):
  """
  Negotiate with a socks4a server. Closes the socket and raises an exception on
  failure.

  :param socket sock: socket connected to socks4a server
  :param str host: hostname/IP to connect to
  :param int port: port to connect to

  :raises: :class:`stem.ProtocolError` if the socks server doesn't grant our request

  :returns: a list with the IP address and the port that the proxy connected to
  """

  # SOCKS4a request here - http://en.wikipedia.org/wiki/SOCKS#Protocol
  request = "\x04\x01" + struct.pack("!H", port) + "\x00\x00\x00\x01" + "\x00" + host + "\x00"
  sock.sendall(request)
  response = sock.recv(8)

  if len(response) != 8 or response[0] != "\x00" or response[1] != "\x5a":
    sock.close()
    raise ProtocolError(error_msgs.get(response[1], "SOCKS server returned unrecognized error code"))

  return [socket.inet_ntoa(response[4:]), struct.unpack("!H", response[2:4])[0]]
