"""
Simple helper methods to make troubleshooting with the python interpreter
easier.

::

  >>> from test.prompt import *
  >>> controller = controller()
  >>> controller.get_info("version")
  '0.2.1.30'
  
  >>> is_running()
  True
  
  >>> stop()
"""

import os
import signal
import sys

import stem.control
import stem.process
import stem.util.system

CONTROL_PORT = 2779

STOP_CONFIRMATION = "Would you like to stop the tor instance we made? (y/n, default: n): "

def print_usage():
  """
  Provides a welcoming message.
  """
  
  print "Welcome to stem's testing prompt. You currently have a controller available"
  print "via the 'controller' variable."
  print

def start():
  """
  Starts up a tor instance that we can attach a controller to.
  """
  
  tor_config = {
    'SocksPort': '0',
    'ControlPort': str(CONTROL_PORT),
    'ExitPolicy': 'reject *:*',
  }
  
  sys.stdout.write("Starting tor...")
  stem.process.launch_tor_with_config(config = tor_config, completion_percent = 5)
  sys.stdout.write("  done\n\n")

def stop(prompt = False):
  """
  Stops the tor instance spawned by this module.
  
  :param bool prompt: asks user for confirmation that they would like to stop tor if True
  """
  
  tor_pid = stem.util.system.get_pid_by_port(CONTROL_PORT)
  
  if tor_pid:
    if prompt:
      response = raw_input("\n" + STOP_CONFIRMATION)
      if not response.lower() in ("y", "yes"): return
    
    os.kill(tor_pid, signal.SIGTERM)

def is_running():
  """
  Checks if we're likely running a tor instance spawned by this module. This is
  simply a check if our custom control port is in use, so it can be confused by
  other applications (not likely, but possible).
  
  :returns: True if the control port is used, False otherwise
  """
  
  return bool(stem.util.system.get_pid_by_port(CONTROL_PORT))

def controller():
  """
  Provides a Controller for our tor instance. This starts tor if it isn't
  already running.
  """
  
  if not is_running(): start()
  controller = stem.control.Controller.from_port(control_port = CONTROL_PORT)
  controller.authenticate()
  return controller

