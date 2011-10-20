"""
Helper functions for working with tor as a process. These are mostly os
dependent, only working on linux, osx, and bsd.
"""

import os
import signal
import subprocess

# number of seconds before we time out our attempt to start a tor instance
TOR_INIT_TIMEOUT = 90

def launch_tor(torrc_path, init_msg_handler = None):
  """
  Initializes a tor process. This blocks until initialization completes or we
  error out.
  
  Arguments:
    torrc_path (str)           - location of the torrc for us to use
    init_msg_handler (functor) - optional functor that will be provided with
                                 tor's initialization stdout as we get it
  
  Returns:
    subprocess.Popen instance for the tor subprocess
  
  Raises:
    OSError if we either fail to create the tor process or reached a timeout
    without success
  """
  
  # double check that we have a torrc to work with
  if not os.path.exists(torrc_path):
    raise OSError("torrc doesn't exist (%s)" % torrc_path)
  
  # starts a tor subprocess, raising an OSError if it fails
  tor_process = subprocess.Popen(["tor", "-f", torrc_path], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
  
  # time ourselves out if we reach TOR_INIT_TIMEOUT
  def timeout_handler(signum, frame):
    # terminates the uninitialized tor process and raise on timeout
    tor_process.kill()
    raise OSError("reached a %i second timeout without success" % TOR_INIT_TIMEOUT)
  
  signal.signal(signal.SIGALRM, timeout_handler)
  signal.alarm(TOR_INIT_TIMEOUT)
  
  while True:
    init_line = tor_process.stdout.readline().strip()
    
    # this will provide empty results if the process is terminated
    if not init_line:
      tor_process.kill() # ... but best make sure
      raise OSError("process terminated")
    
    # provide the caller with the initialization message if they want it
    if init_msg_handler: init_msg_handler(init_line)
    
    # return the process if we're done with bootstrapping
    if init_line.endswith("Bootstrapped 100%: Done."):
      return tor_process

