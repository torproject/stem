"""
Helper functions for working with tor as a process. These are mostly os
dependent, only working on linux, osx, and bsd.

launch_tor - starts up a tor process
"""

import re
import os
import signal
import tempfile
import subprocess

# number of seconds before we time out our attempt to start a tor instance
DEFAULT_INIT_TIMEOUT = 90

# special parameter that can be set for the torrc_path to run with a blank
# configuration

NO_TORRC = "<no torrc>"

def launch_tor(tor_cmd = "tor", options = None, torrc_path = None, completion_percent = 100, init_msg_handler = None, timeout = DEFAULT_INIT_TIMEOUT):
  """
  Initializes a tor process. This blocks until initialization completes or we
  error out.
  
  If tor's data directory is missing or stale then bootstrapping will include
  making several requests to the directory authorities which can take a little
  while. Usually this is done in 50 seconds or so, but occasionally calls seem
  to get stuck, taking well over the default timeout.
  
  Arguments:
    tor_cmd (str)              - command for starting tor
    options (dict)             - configuration options, such as ("ControlPort": "9051")
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
  if not torrc_path in (None, NO_TORRC) and not os.path.exists(torrc_path):
    raise OSError("torrc doesn't exist (%s)" % torrc_path)
  
  # starts a tor subprocess, raising an OSError if it fails
  runtime_args, temp_file = [tor_cmd], None
  if torrc_path:
    if torrc_path == NO_TORRC:
      temp_file = tempfile.mkstemp("-empty-torrc", text = True)[1]
      runtime_args += ["-f", temp_file]
    else:
      runtime_args += ["-f", torrc_path]
  
  if options:
    for key, value in options.items():
      value = value.replace('"', '\\"')
      runtime_args += ["--%s" % key.lower(), value]
  
  tor_process = subprocess.Popen(runtime_args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
  
  if timeout:
    def timeout_handler(signum, frame):
      # terminates the uninitialized tor process and raise on timeout
      if temp_file:
        try: os.remove(temp_file)
        except: pass
      
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
      if temp_file:
        try: os.remove(temp_file)
        except: pass
      
      return tor_process

