"""
Helper functions for working with tor as a process.

launch_tor             - starts up a tor process
launch_tor_with_config - starts a tor process with a custom torrc
"""

import re
import os
import signal
import tempfile
import subprocess

import stem.util.system

# number of seconds before we time out our attempt to start a tor instance
DEFAULT_INIT_TIMEOUT = 90

# special parameter that can be set for the torrc_path to run with a blank
# configuration

NO_TORRC = "<no torrc>"

def launch_tor(tor_cmd = "tor", args = None, torrc_path = None, completion_percent = 100, init_msg_handler = None, timeout = DEFAULT_INIT_TIMEOUT):
  """
  Initializes a tor process. This blocks until initialization completes or we
  error out.
  
  If tor's data directory is missing or stale then bootstrapping will include
  making several requests to the directory authorities which can take a little
  while. Usually this is done in 50 seconds or so, but occasionally calls seem
  to get stuck, taking well over the default timeout.
  
  Our timeout argument does not work on Windows...
  https://trac.torproject.org/projects/tor/ticket/5783
  
  Arguments:
    tor_cmd (str)              - command for starting tor
    args (list)                - additional arguments for tor
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
  
  if stem.util.system.is_windows():
    timeout = None
  
  # double check that we have a torrc to work with
  if not torrc_path in (None, NO_TORRC) and not os.path.exists(torrc_path):
    raise OSError("torrc doesn't exist (%s)" % torrc_path)
  
  # starts a tor subprocess, raising an OSError if it fails
  runtime_args, temp_file = [tor_cmd], None
  if args: runtime_args += args
  
  if torrc_path:
    if torrc_path == NO_TORRC:
      temp_file = tempfile.mkstemp(prefix = "empty-torrc-", text = True)[1]
      runtime_args += ["-f", temp_file]
    else:
      runtime_args += ["-f", torrc_path]
  
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
  problem_line = re.compile("\[(warn|err)\] (.*)$")
  last_problem = "Timed out"
  
  while True:
    init_line = tor_process.stdout.readline().strip()
    
    # this will provide empty results if the process is terminated
    if not init_line:
      tor_process.kill() # ... but best make sure
      raise OSError("Process terminated: %s" % last_problem)
    
    # provide the caller with the initialization message if they want it
    if init_msg_handler: init_msg_handler(init_line)
    
    # return the process if we're done with bootstrapping
    bootstrap_match = bootstrap_line.search(init_line)
    problem_match = problem_line.search(init_line)
    
    if bootstrap_match and int(bootstrap_match.groups()[0]) >= completion_percent:
      if temp_file:
        try: os.remove(temp_file)
        except: pass
      
      return tor_process
    elif problem_match:
      runlevel, msg = problem_match.groups()
      
      if not "see warnings above" in msg:
        if ": " in msg: msg = msg.split(": ")[-1].strip()
        last_problem = msg

def launch_tor_with_config(config, tor_cmd = "tor", completion_percent = 100, init_msg_handler = None, timeout = DEFAULT_INIT_TIMEOUT):
  """
  Initializes a tor process, like launch_tor(), but with a customized
  configuration. This writes a temporary torrc to disk, launches tor, then
  deletes the torrc.
  
  Arguments:
    config (dict)              - configuration options, such as ("ControlPort": "9051")
    tor_cmd (str)              - command for starting tor
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
  
  torrc_path = tempfile.mkstemp(prefix = "torrc-", text = True)[1]
  
  try:
    with open(torrc_path, "w") as torrc_file:
      for key, value in config.items():
        torrc_file.write("%s %s\n" % (key, value))
    
    return launch_tor(tor_cmd, None, torrc_path, completion_percent, init_msg_handler, timeout)
  finally:
    try: os.remove(torrc_path)
    except: pass

