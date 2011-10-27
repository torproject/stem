"""
Helper functions for working with tor as a process. These are mostly os
dependent, only working on linux, osx, and bsd.
"""

import re
import os
import signal
import subprocess

import stem.types

from stem.util import system

# number of seconds before we time out our attempt to start a tor instance
DEFAULT_INIT_TIMEOUT = 90

def get_version(tor_cmd = "tor"):
  """
  Provides the version of tor.
  
  Arguments:
    tor_cmd (str) - command used to run tor
  
  Returns:
    stem.types.Version provided by the tor command
  
  Raises:
    IOError if unable to query or parse the version
  """
  
  try:
    version_cmd = "%s --version" % tor_cmd
    version_output = system.call(version_cmd)
  except OSError, exc:
    raise IOError(exc)
  
  if version_output:
    # output example:
    # Oct 21 07:19:27.438 [notice] Tor v0.2.1.30. This is experimental software. Do not rely on it for strong anonymity. (Running on Linux i686)
    # Tor version 0.2.1.30.
    
    last_line = version_output[-1]
    
    if last_line.startswith("Tor version ") and last_line.endswith("."):
      try:
        version_str = last_line[12:-1]
        return stem.types.get_version(version_str)
      except ValueError, exc:
        raise IOError(exc)
    else:
      raise IOError("Unexpected response from '%s': %s" % (version_cmd, last_line))
  else:
    raise IOError("'%s' didn't have any output" % version_cmd)

def launch_tor(torrc_path, completion_percent = 100, init_msg_handler = None, timeout = DEFAULT_INIT_TIMEOUT):
  """
  Initializes a tor process. This blocks until initialization completes or we
  error out.
  
  If tor's data directory is missing or stale then bootstrapping will include
  making several requests to the directory authorities which can take a little
  while. Usually this is done in 50 seconds or so, but occasionally calls seem
  to get stuck, taking well over the default timeout.
  
  Arguments:
    torrc_path (str)           - location of the torrc for us to use
    completion_percent (int)   - percent of bootstrap completion at which
                                 this'll return
    init_msg_handler (functor) - optional functor that will be provided with
                                 tor's initialization stdout as we get it
    timeout (int)              - time after which the attempt to start tor is
                                 aborted, no timeouts are applied if None
  
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
  
  if timeout:
    def timeout_handler(signum, frame):
      # terminates the uninitialized tor process and raise on timeout
      tor_process.kill()
      raise OSError("reached a %i second timeout without success" % timeout)
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
  
  bootstrap_line = re.compile("Bootstrapped ([0-9]+)%: ")
  
  while True:
    init_line = tor_process.stdout.readline().strip()
    
    # this will provide empty results if the process is terminated
    if not init_line:
      tor_process.kill() # ... but best make sure
      raise OSError("process terminated")
    
    # provide the caller with the initialization message if they want it
    if init_msg_handler: init_msg_handler(init_line)
    
    # return the process if we're done with bootstrapping
    bootstrap_match = bootstrap_line.search(init_line)
    
    if bootstrap_match and int(bootstrap_match.groups()[0]) >= completion_percent:
      return tor_process

