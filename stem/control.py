"""
Classes for interacting with the tor control socket.

Controllers are a wrapper around a ControlSocket, retaining its low-level
connection methods (send, recv, is_alive, etc) in addition to providing methods
for interacting at a higher level.
"""

import stem.socket

class BaseController(stem.socket.ControlSocket):
  """
  Controller for the tor process. This is a minimal base class for other
  controllers, providing basic process communication and event listing. Don't
  use this directly - subclasses provide higher level functionality.
  
  Attributes:
    socket - ControlSocket from which this was constructed
  """
  
  def __init__(self, control_socket):
    self.socket = control_socket
  
  def send(self, message, raw = False):
    self.socket.send(message, raw)
  
  def recv(self):
    return self.socket.recv()
  
  def is_alive(self):
    return self.socket.is_alive()
  
  def connect(self):
    self.socket.connect()
  
  def close(self):
    self.socket.close()
  
  def _make_socket(self):
    self._control_socket._make_socket()

