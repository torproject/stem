"""
Helper functions for working with the underlying system. These are mostly os
dependent, only working on linux, osx, and bsd.
"""

import os
import time
import subprocess

from stem.util import log

# Mapping of commands to if they're available or not. This isn't always
# reliable, failing for some special commands. For these the cache is
# prepopulated to skip lookups.
CMD_AVAILABLE_CACHE = {"ulimit": True}

def is_available(command, cached=True):
  """
  Checks the current PATH to see if a command is available or not. If more
  than one command is present (for instance "ls -a | grep foo") then this
  just checks the first.
  
  Arguments:
    command (str) - command to search for
    cached (bool) - makes use of available cached results if True
  
  Returns:
    True if an executable we can use by that name exists in the PATH, False
    otherwise
  """
  
  if " " in command: command = command.split(" ")[0]
  
  if cached and command in CMD_AVAILABLE_CACHE:
    return CMD_AVAILABLE_CACHE[command]
  else:
    cmd_exists = False
    for path in os.environ["PATH"].split(os.pathsep):
      cmd_path = os.path.join(path, command)
      
      if os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
        cmd_exists = True
        break
    
    CMD_AVAILABLE_CACHE[command] = cmd_exists
    return cmd_exists

def is_running(command, suppress_exc = True):
  """
  Checks for if a process with a given name is running or not.
  
  Arguments:
    command (str)       - process name to be checked
    suppress_exc (bool) - if True then None is returned on failure, otherwise
                          this raises the exception
  
  Returns:
    True if the process is running, False otherwise
  
  Raises:
    OSError if this can't be determined and suppress_exc is False
  """
  
  # Linux and the BSD families have different variants of ps. Guess based on
  # os.uname() results which to try first, then fall back to the other.
  #
  # Linux
  #   -A          - Select all processes. Identical to -e.
  #   -co command - Shows just the base command.
  #
  # Mac / BSD
  #   -a        - Display information about other users' processes as well as
  #               your own.
  #   -o ucomm= - Shows just the ucomm attribute ("name to be used for
  #               accounting")
  
  primary_resolver, secondary_resolver = "ps -A co command", "ps -ao ucomm="
  
  if os.uname()[0] in ("Darwin", "FreeBSD", "OpenBSD"):
    primary_resolver, secondary_resolver = secondary_resolver, primary_resolver
  
  command_listing = call(primary_resolver)
  if not command_listing:
    command_listing = call(secondary_resolver)
  
  if command_listing:
    return command in command_listing
  else:
    if suppress_exc: return None
    else: raise OSError("Unable to check via 'ps -A co command'")

def call(command, suppress_exc = True):
  """
  Issues a command in a subprocess, blocking until completion and returning the
  results. This is not actually ran in a shell so pipes and other shell syntax
  aren't permitted.
  
  Arguments:
    command (str)       - command to be issued
    suppress_exc (bool) - if True then None is returned on failure, otherwise
                          this raises the exception
  
  Returns:
    List with the lines of output from the command, None in case of failure if
    suppress_exc is True
  
  Raises:
    OSError if this fails and suppress_exc is False
  """
  
  try:
    start_time = time.time()
    stdout, stderr = subprocess.Popen(command.split(), stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()
    stdout, stderr = stdout.strip(), stderr.strip()
    runtime = time.time() - start_time
    
    msg = "system call: %s (runtime: %0.2f)" % (command, runtime)
    if stderr: msg += "\nstderr: %s" % stderr
    log.log(log.DEBUG, msg)
    
    if stdout: return stdout.split("\n")
    else: return []
  except OSError, exc:
    msg = "system call (failed): %s (error: %s)" % (command, exc)
    log.log(log.INFO, msg)
    
    if suppress_exc: return None
    else: raise exc

