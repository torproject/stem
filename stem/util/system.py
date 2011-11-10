"""
Helper functions for working with the underlying system. These are mostly os
dependent, only working on linux, osx, and bsd.
"""

import re
import os
import time
import logging
import subprocess

import stem.util.proc

LOGGER = logging.getLogger("stem")

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

def get_pid(process_name, process_port = None):
  """
  Attempts to determine the process id for a running process, using the
  following:
  
  1. "pgrep -x <name>"
  2. "pidof <name>"
  3. "netstat -npl | grep 127.0.0.1:<port>"
  4. "ps -o pid -C <name>"
  5. "sockstat -4l -P tcp -p <port> | grep <name>"
  6. "ps axc | egrep \" <name>$\""
  7. "lsof -wnPi | egrep \"^<name>.*:<port>\""
  
  If pidof or ps provide multiple instance of the process then their results
  are discarded (since only netstat can differentiate using a bound port).
  
  Arguments:
    process_name (str) - process name for which to fetch the pid
    process_port (int) - port that the process we're interested in is bound to,
                         this is used to disambiguate if there's multiple
                         instances running
  
  Returns:
    int with the process id, None if either no running process exists or it
    can't be determined
  """
  
  # attempts to resolve using pgrep, failing if:
  # - the process is running under a different name
  # - there are multiple instances
  
  try:
    results = call("pgrep -x %s" % process_name)
    
    if results and len(results) == 1 and len(results[0].split()) == 1:
      pid = results[0].strip()
      if pid.isdigit(): return int(pid)
  except IOError: pass
  
  # attempts to resolve using pidof, failing if:
  # - the process is running under a different name
  # - there are multiple instances
  
  try:
    results = call("pidof %s" % process_name)
    
    if results and len(results) == 1 and len(results[0].split()) == 1:
      pid = results[0].strip()
      if pid.isdigit(): return int(pid)
  except IOError: pass
  
  # attempts to resolve using netstat, failing if:
  # - the process being run as a different user due to permissions
  
  if process_port:
    try:
      results = call("netstat -npl")
      
      # filters to results with our port (same as "grep 127.0.0.1:<port>")
      if results:
        results = [r for r in results if "127.0.0.1:%i" % process_port in r]
        
        if len(results) == 1:
          results = results[0].split()[6] # process field (ex. "7184/tor")
          pid = results[:results.find("/")]
          if pid.isdigit(): return int(pid)
    except IOError: pass
  
  # attempts to resolve using ps, failing if:
  # - the process is running under a different name
  # - there are multiple instances
  
  try:
    results = call("ps -o pid -C %s" % process_name)
    
    if results and len(results) == 2:
      pid = results[1].strip()
      if pid.isdigit(): return int(pid)
  except IOError: pass
  
  # attempts to resolve using sockstat, failing if:
  # - sockstat doesn't accept the -4 flag (BSD only)
  # - the process is running under a different name
  # - there are multiple instances using the same port on different addresses
  # 
  # TODO: The later two issues could be solved by filtering for an expected IP
  # address instead of the process name.
  
  if process_port:
    try:
      results = call("sockstat -4l -P tcp -p %i" % process_port)
      
      # filters to results with our port (same as "grep <name>")
      if results:
        results = [r for r in results if process_name in r]
        
        if len(results) == 1 and len(results[0].split()) == 7:
          pid = results[0].split()[2]
          if pid.isdigit(): return int(pid)
    except IOError: pass
  
  # attempts to resolve via a ps command that works on mac/bsd (this and lsof
  # are the only resolvers to work on that platform). This fails if:
  # - the process is running under a different name
  # - there are multiple instances
  
  try:
    results = call("ps axc")
    
    # filters to results with our port (same as "egrep ' <name>$'")
    if results:
      results = [r for r in results if r.endswith(" %s" % process_name)]
      
      if len(results) == 1 and len(results[0].split()) > 0:
        pid = results[0].split()[0]
        if pid.isdigit(): return int(pid)
  except IOError: pass
  
  # attempts to resolve via lsof, this should work on linux, mac, and bsd
  # and only fail if:
  # - the process is running under a different name
  # - the process being run as a different user due to permissions
  # - there are multiple instances using the same port on different addresses
  
  try:
    results = call("lsof -wnPi")
    
    # filters to results with our port (same as "egrep '^<name>.*:<port>'")
    if results:
      port_comp = str(process_port) if process_port else ""
      results = [r for r in results if re.match("^%s.*:%s" % (process_name, port_comp), r)]
    
    # This can result in multiple entries with the same pid (from the query
    # itself). Checking all lines to see if they're in agreement about the pid.
    
    if results:
      pid = ""
      
      for line in results:
        line_comp = line.split()
        
        if len(line_comp) >= 2 and (not pid or line_comp[1] == pid):
          pid = line_comp[1]
        else: raise IOError
      
      if pid.isdigit(): return int(pid)
  except IOError: pass
  
  return None

def get_pwd(pid):
  """
  Provices the working directory of the given process.
  
  Arguments:
    pid (int) - process id of the process to be queried
  
  Returns:
    str with the absolute path for the process' present working directory
  
  Raises:
    IOError if it can't be determined
  """
  
  # try fetching via the proc contents if it's available
  if stem.util.proc.is_available():
    try: return stem.util.proc.get_pwd(pid)
    except IOError: pass
  
  # Fall back to a pwdx query. This isn't available on BSD. If we attempt this
  # lookup then it trumps lsof when reporting an exception at the end since
  # it's the better lookup method for this information.
  
  exc_msg = None
  
  if is_available("pwdx"):
    # pwdx results are of the form:
    # 3799: /home/atagar
    # 5839: No such process
    
    try:
      results = call("pwdx %s" % pid)
      
      if not results:
        exc_msg = "pwdx didn't return any results"
      elif results[0].endswith("No such process"):
        exc_msg = "pwdx reported no process for pid %s" % pid
      elif len(results) != 1 or results[0].count(" ") != 1:
        exc_msg = "we got unexpected output from pwdx: %s" % results
      else:
        return results[0].split(" ", 1)[1].strip()
    except OSError, exc:
      exc_msg = "pwdx query for %s failed: %s" % (pid, exc)
  
  # Use lsof as the final fallback. This is available on both Linux and is the
  # only lookup method here that works for BSD...
  # https://trac.torproject.org/projects/tor/ticket/4236
  #
  # ~$ lsof -a -p 75717 -d cwd -Fn
  # p75717
  # n/Users/atagar/tor/src/or
  
  try:
    results = call("lsof -a -p %s -d cwd -Fn" % pid)
    
    if results and len(results) == 2 and results[1].startswith("n/"):
      return results[1][1:].strip()
    elif not exc_msg:
      exc_msg = "we got unexpected output from lsof: %s" % results
  except OSError, exc:
    if not exc_msg:
      exc_msg = "lsof query for the pwd of %s failed: %s" % (pid, exc)
  
  if not exc_msg:
    # shouldn't happen, somehow we never registered a failure...
    exc_msg = "unable to query pwdx or lsof"
  
  # we failed all lookups, raise
  raise IOError(exc_msg)

def get_bsd_jail_id(pid):
  """
  Get the FreeBSD jail id for a process.
  
  Arguments:
    pid (int) - process id of the jail id to be queried
  
  Returns:
    int for the jail id, zero if this can't be determined
  """
  
  # Output when called from a FreeBSD jail or when Tor isn't jailed:
  #   JID
  #    0
  # 
  # Otherwise it's something like:
  #   JID
  #    1
  
  ps_output = call("ps -p %s -o jid" % pid)
  
  if len(ps_output) == 2 and len(ps_output[1].split()) == 1:
    jid = ps_output[1].strip()
    if jid.isdigit(): return int(jid)
  
  LOGGER.warn("Failed to figure out the FreeBSD jail id. Assuming 0.")
  return 0

def call(command, suppress_exc = True):
  """
  Issues a command in a subprocess, blocking until completion and returning the
  results. This is not actually ran in a shell so pipes and other shell syntax
  are not permitted.
  
  Arguments:
    command (str)       - command to be issued
    suppress_exc (bool) - if True then None is returned on failure, otherwise
                          this raises the exception
  
  Returns:
    list with the lines of output from the command, None in case of failure if
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
    LOGGER.debug(msg)
    
    if stdout: return stdout.split("\n")
    else: return []
  except OSError, exc:
    msg = "system call (failed): %s (error: %s)" % (command, exc)
    LOGGER.debug(msg)
    
    if suppress_exc: return None
    else: raise exc

