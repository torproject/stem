"""
Helper functions for working with the underlying system. These are mostly os
dependent, only working on linux, osx, and bsd. In almost all cases they're
best-effort, providing **None** if the lookup fails.

**Module Overview:**

::

  is_windows - checks if we're running on windows
  is_mac - checks if we're running on a mac
  is_bsd - checks if we're running on the bsd family of operating systems
  is_available - determines if a command is available on this system
  is_running - determines if a given process is running
  get_pid_by_name - gets the pid for a process by the given name
  get_pid_by_port - gets the pid for a process listening to a given port
  get_pid_by_open_file - gets the pid for the process with an open file
  get_cwd - provides the current working directory for a given process
  get_bsd_jail_id - provides the BSD jail id a given process is running within
  expand_path - expands relative paths and ~ entries
  call - runs the given system command and provides back the results
"""

import os
import platform
import subprocess
import time

import stem.util.proc

from stem import UNDEFINED, CircStatus
from stem.util import log

# Mapping of commands to if they're available or not.

CMD_AVAILABLE_CACHE = {}

# An incomplete listing of commands provided by the shell. Expand this as
# needed. Some noteworthy things about shell commands...
#
# * They're not in the path so is_available() will fail.
# * subprocess.Popen() without the 'shell = True' argument will fail with...
#   OSError: [Errno 2] No such file or directory

SHELL_COMMANDS = ['ulimit']

IS_RUNNING_PS_LINUX = "ps -A co command"
IS_RUNNING_PS_BSD = "ps -ao ucomm="
GET_PID_BY_NAME_PGREP = "pgrep -x %s"
GET_PID_BY_NAME_PIDOF = "pidof %s"
GET_PID_BY_NAME_PS_LINUX = "ps -o pid -C %s"
GET_PID_BY_NAME_PS_BSD = "ps axc"
GET_PID_BY_NAME_LSOF = "lsof -tc %s"
GET_PID_BY_PORT_NETSTAT = "netstat -npltu"
GET_PID_BY_PORT_SOCKSTAT = "sockstat -4l -P tcp -p %s"
GET_PID_BY_PORT_LSOF = "lsof -wnP -iTCP -sTCP:LISTEN"
GET_PID_BY_FILE_LSOF = "lsof -tw %s"
GET_CWD_PWDX = "pwdx %s"
GET_CWD_LSOF = "lsof -a -p %s -d cwd -Fn"
GET_BSD_JAIL_ID_PS = "ps -p %s -o jid"

def is_windows():
  """
  Checks if we are running on Windows.
  
  :returns: **bool** to indicate if we're on Windows
  """
  
  return platform.system() == "Windows"

def is_mac():
  """
  Checks if we are running on Mac OSX.
  
  :returns: **bool** to indicate if we're on a Mac
  """
  
  return platform.system() == "Darwin"

def is_bsd():
  """
  Checks if we are within the BSD family of operating systems. This presently
  recognizes Macs, FreeBSD, and OpenBSD but may be expanded later.
  
  :returns: **bool** to indicate if we're on a BSD OS
  """
  
  return platform.system() in ("Darwin", "FreeBSD", "OpenBSD")

def is_available(command, cached=True):
  """
  Checks the current PATH to see if a command is available or not. If more
  than one command is present (for instance "ls -a | grep foo") then this
  just checks the first.
  
  Note that shell (like cd and ulimit) aren't in the PATH so this lookup will
  try to assume that it's available. This only happends for recognized shell
  commands (those in SHELL_COMMANDS).
  
  :param str command: command to search for
  :param bool cached: makes use of available cached results if **True**
  
  :returns: **True** if an executable we can use by that name exists in the
    PATH, **False** otherwise
  """
  
  if " " in command:
    command = command.split(" ")[0]
  
  if command in SHELL_COMMANDS:
    # we can't actually look it up, so hope the shell really provides it...
    
    return True
  elif cached and command in CMD_AVAILABLE_CACHE:
    return CMD_AVAILABLE_CACHE[command]
  else:
    cmd_exists = False
    for path in os.environ["PATH"].split(os.pathsep):
      cmd_path = os.path.join(path, command)
      
      if is_windows():
        cmd_path += ".exe"
      
      if os.path.exists(cmd_path) and os.access(cmd_path, os.X_OK):
        cmd_exists = True
        break
    
    CMD_AVAILABLE_CACHE[command] = cmd_exists
    return cmd_exists

def is_running(command):
  """
  Checks for if a process with a given name is running or not.
  
  :param str command: process name to be checked
  
  :returns: **True** if the process is running, **False** if it's not among ps
    results, and **None** if ps can't be queried
  """
  
  # Linux and the BSD families have different variants of ps. Guess based on
  # the is_bsd() check which to try first, then fall back to the other.
  #
  # Linux
  #   -A          - Select all processes.
  #   -co command - Shows just the base command.
  #
  # Mac / BSD
  #   -a        - Display information about other users' processes as well as
  #               our own.
  #   -o ucomm= - Shows just the ucomm attribute ("name to be used for
  #               accounting")
  
  if is_available("ps"):
    if is_bsd():
      primary_resolver = IS_RUNNING_PS_BSD
      secondary_resolver = IS_RUNNING_PS_LINUX
    else:
      primary_resolver = IS_RUNNING_PS_LINUX
      secondary_resolver = IS_RUNNING_PS_BSD
    
    command_listing = call(primary_resolver)
    if not command_listing:
      command_listing = call(secondary_resolver)
    
    if command_listing:
      command_listing = map(str.strip, command_listing)
      return command in command_listing
  
  return None

def get_pid_by_name(process_name):
  """
  Attempts to determine the process id for a running process, using...
  
  ::
  
    1. pgrep -x <name>
    2. pidof <name>
    3. ps -o pid -C <name> (linux)
       ps axc | egrep " <name>$" (bsd)
    4. lsof -tc <name>
  
  Results with multiple instances of the process are discarded.
  
  :param str process_name: process name for which to fetch the pid
  
  :returns: **int** with the process id, **None** if it can't be determined
  """
  
  # attempts to resolve using pgrep, failing if:
  # - we're running on bsd (command unavailable)
  #
  # example output:
  #   atagar@morrigan:~$ pgrep -x vim
  #   3283
  #   3392
  
  if is_available("pgrep"):
    results = call(GET_PID_BY_NAME_PGREP % process_name)
    
    if results and len(results) == 1:
      pid = results[0].strip()
      
      if pid.isdigit():
        return int(pid)
  
  # attempts to resolve using pidof, failing if:
  # - we're running on bsd (command unavailable)
  #
  # example output:
  #   atagar@morrigan:~$ pidof vim
  #   3392 3283
  
  if is_available("pidof"):
    results = call(GET_PID_BY_NAME_PIDOF % process_name)
    
    if results and len(results) == 1 and len(results[0].split()) == 1:
      pid = results[0].strip()
      
      if pid.isdigit():
        return int(pid)
  
  # attempts to resolve using ps, failing if:
  # - system's ps variant doesn't handle these flags (none known at the moment)
  #
  # example output:
  #   atagar@morrigan:~/Desktop/stem$ ps -o pid -C vim
  #     PID
  #    3283
  #    3392
  #
  #   atagar$ ps axc
  #     PID   TT  STAT      TIME COMMAND
  #       1   ??  Ss     9:00.22 launchd
  #      10   ??  Ss     0:09.97 kextd
  #      11   ??  Ss     5:47.36 DirectoryService
  #      12   ??  Ss     3:01.44 notifyd
  
  if is_available("ps"):
    if not is_bsd():
      # linux variant of ps
      results = call(GET_PID_BY_NAME_PS_LINUX % process_name)
      
      if results and len(results) == 2:
        pid = results[1].strip()
        
        if pid.isdigit():
          return int(pid)
    
    if is_bsd():
      # bsd variant of ps
      results = call(GET_PID_BY_NAME_PS_BSD)
      
      if results:
        # filters results to those with our process name
        results = [r for r in results if r.endswith(" %s" % process_name)]
        
        if len(results) == 1 and len(results[0].split()) > 0:
          pid = results[0].split()[0]
          
          if pid.isdigit():
            return int(pid)
  
  # resolves using lsof which works on both Linux and BSD, only failing if:
  # - lsof is unavailable (not included by default on OpenBSD)
  # - the process being run as a different user due to permissions
  # - the process doesn't have any open files to be reported by lsof?
  #
  # flags:
  #   t - only show pids
  #   c - restrict results to that command
  #
  # example output:
  #   atagar@morrigan:~$ lsof -t -c vim
  #   2470
  #   2561
  
  if is_available("lsof"):
    results = call(GET_PID_BY_NAME_LSOF % process_name)
    
    if results and len(results) == 1:
      pid = results[0].strip()
      
      if pid.isdigit():
        return int(pid)
  
  log.debug("failed to resolve a pid for '%s'" % process_name)
  return None

def get_pid_by_port(port):
  """
  Attempts to determine the process id for a process with the given port,
  using...
  
  ::
  
    1. netstat -npltu | grep 127.0.0.1:<port>
    2. sockstat -4l -P tcp -p <port>
    3. lsof -wnP -iTCP -sTCP:LISTEN | grep ":<port>"
  
  Most queries limit results to listening TCP connections. This function likely
  won't work on Mac OSX.
  
  :param int port: port where the process we're looking for is listening
  
  :returns: **int** with the process id, **None** if it can't be determined
  """
  
  # attempts to resolve using netstat, failing if:
  # - netstat doesn't accept these flags (Linux only)
  # - the process being run as a different user due to permissions
  #
  # flags:
  #   n - numeric (disables hostname lookups)
  #   p - program (include pids)
  #   l - listening (include listening sockets)
  #   tu - show tcp and udp sockets, and nothing else
  #
  # example output:
  #   atagar@morrigan:~$ netstat -npltu
  #   Active Internet connections (only servers)
  #   Proto Recv-Q Send-Q Local Address           Foreign Address   State    PID/Program name
  #   tcp        0      0 127.0.0.1:631           0.0.0.0:*         LISTEN   -
  #   tcp        0      0 127.0.0.1:9051          0.0.0.0:*         LISTEN   1641/tor
  #   tcp6       0      0 ::1:631                 :::*              LISTEN   -
  #   udp        0      0 0.0.0.0:5353            0.0.0.0:*                  -
  #   udp6       0      0 fe80::7ae4:ff:fe2f::123 :::*                       -
  
  if is_available("netstat"):
    results = call(GET_PID_BY_PORT_NETSTAT)
    
    if results:
      # filters to results with our port
      results = [r for r in results if "127.0.0.1:%s" % port in r]
      
      if len(results) == 1 and len(results[0].split()) == 7:
        results = results[0].split()[6]  # process field (ex. "7184/tor")
        pid = results[:results.find("/")]
        
        if pid.isdigit():
          return int(pid)
  
  # attempts to resolve using sockstat, failing if:
  # - sockstat doesn't accept the -4 flag (BSD only)
  # - sockstat isn't available (encountered with OSX 10.5.8)
  # - there are multiple instances using the same port on different addresses
  #
  # flags:
  #   4 - only show IPv4 sockets
  #   l - listening sockets
  #   P tcp - only show tcp connections
  #   p - only includes results if the local or foreign port match this
  #
  # example output:
  #   # TODO: We need an example for the actual command we're using. I'm
  #   # suspecting that replacing the grep with checking the local port works,
  #   # but should double check.
  #
  #   # sockstat -4 | grep tor
  #   _tor     tor        4397  7  tcp4   51.64.7.84:9050    *:*
  #   _tor     tor        4397  8  udp4   51.64.7.84:53      *:*
  #   _tor     tor        4397  12 tcp4   51.64.7.84:54011   80.3.121.7:9001
  #   _tor     tor        4397  15 tcp4   51.64.7.84:59374   7.42.1.102:9001
  #   _tor     tor        4397  20 tcp4   51.64.7.84:51946   32.83.7.104:443
  
  if is_available("sockstat"):
    results = call(GET_PID_BY_PORT_SOCKSTAT % port)
    
    if results:
      # filters to results where this is the local port
      results = [r for r in results if (len(r.split()) == 7 and (":%s" % port) in r.split()[5])]
      
      if len(results) == 1:
        pid = results[0].split()[2]
        
        if pid.isdigit():
          return int(pid)
  
  # resolves using lsof which works on both Linux and BSD, only failing if:
  # - lsof is unavailable (not included by default on OpenBSD)
  # - lsof doesn't provide the port ip/port, nor accept the -i and -s args
  #   (encountered with OSX 10.5.8)
  # - the process being run as a different user due to permissions
  # - there are multiple instances using the same port on different addresses
  #
  # flags:
  #   w - disables warning messages
  #   n - numeric addresses (disables hostname lookups)
  #   P - numeric ports (disables replacement of ports with their protocol)
  #   iTCP - only show tcp connections
  #   sTCP:LISTEN - listening sockets
  #
  # example output:
  #   atagar@morrigan:~$ lsof -wnP -iTCP -sTCP:LISTEN
  #   COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
  #   tor     1745 atagar    6u  IPv4  14229      0t0  TCP 127.0.0.1:9051 (LISTEN)
  
  if is_available("lsof"):
    results = call(GET_PID_BY_PORT_LSOF)
    
    if results:
      # filters to results with our port
      results = [r for r in results if (len(r.split()) == 10 and (":%s" % port) in r.split()[8])]
      
      if len(results) == 1:
        pid = results[0].split()[1]
        
        if pid.isdigit():
          return int(pid)
  
  return None  # all queries failed

def get_pid_by_open_file(path):
  """
  Attempts to determine the process id for a process with the given open file,
  using...
  
  ::
  
    lsof -w <path>
  
  :param str path: location of the socket file to query against
  
  :returns: **int** with the process id, **None** if it can't be determined
  """
  
  # resolves using lsof which works on both Linux and BSD, only failing if:
  # - lsof is unavailable (not included by default on OpenBSD)
  # - the file can't be read due to permissions
  #
  # flags:
  #   t - only show pids
  #   w - disables warning messages
  #
  # example output:
  #   atagar@morrigan:~$ lsof -tw /tmp/foo
  #   4762
  
  if is_available("lsof"):
    results = call(GET_PID_BY_FILE_LSOF % path)
    
    if results and len(results) == 1:
      pid = results[0].strip()
      
      if pid.isdigit():
        return int(pid)
  
  return None  # all queries failed

def get_cwd(pid):
  """
  Provides the working directory of the given process.
  
  :param int pid: process id of the process to be queried
  :returns: **str** with the absolute path for the process' present working
    directory, **None** if it can't be determined
  """
  
  # try fetching via the proc contents if it's available
  if stem.util.proc.is_available():
    try:
      return stem.util.proc.get_cwd(pid)
    except IOError:
      pass
  
  # Fall back to a pwdx query. This isn't available on BSD.
  logging_prefix = "get_cwd(%s):" % pid
  
  if is_available("pwdx"):
    # pwdx results are of the form:
    # 3799: /home/atagar
    # 5839: No such process
    
    results = call(GET_CWD_PWDX % pid)
    
    if not results:
      log.debug("%s pwdx didn't return any results" % logging_prefix)
    elif results[0].endswith("No such process"):
      log.debug("%s pwdx processes reported for this pid" % logging_prefix)
    elif len(results) != 1 or results[0].count(" ") != 1 or not results[0].startswith("%s: " % pid):
      log.debug("%s we got unexpected output from pwdx: %s" % (logging_prefix, results))
    else:
      return results[0].split(" ", 1)[1].strip()
  
  # Use lsof as the final fallback. This is available on both Linux and is the
  # only lookup method here that works for BSD...
  # https://trac.torproject.org/projects/tor/ticket/4236
  #
  # flags:
  #   a - presents the intersection of the following arguments
  #   p - limits results to this pid
  #   d cwd - limits results to just the cwd rather than all open files
  #   Fn - short listing in a single column, with just the pid and cwd
  #
  # example output:
  #   ~$ lsof -a -p 75717 -d cwd -Fn
  #   p75717
  #   n/Users/atagar/tor/src/or
  
  if is_available("lsof"):
    results = call(GET_CWD_LSOF % pid)
    
    if results and len(results) == 2 and results[1].startswith("n/"):
      lsof_result = results[1][1:].strip()
      
      # If we lack read permissions for the cwd then it returns...
      # p2683
      # n/proc/2683/cwd (readlink: Permission denied)
      
      if not " " in lsof_result:
        return lsof_result
    else:
      log.debug("%s we got unexpected output from lsof: %s" % (logging_prefix, results))
  
  return None  # all queries failed

def get_bsd_jail_id(pid):
  """
  Gets the jail id for a process. These seem to only exist for FreeBSD (this
  style for jails does not exist on Linux, OSX, or OpenBSD).
  
  :param int pid: process id of the jail id to be queried
  
  :returns: **int** for the jail id, zero if this can't be determined
  """
  
  # Output when called from a FreeBSD jail or when Tor isn't jailed:
  #   JID
  #    0
  #
  # Otherwise it's something like:
  #   JID
  #    1
  
  ps_output = call(GET_BSD_JAIL_ID_PS % pid)
  
  if ps_output and len(ps_output) == 2 and len(ps_output[1].split()) == 1:
    jid = ps_output[1].strip()
    
    if jid.isdigit():
      return int(jid)
  
  os_name = platform.system()
  if os_name == "FreeBSD":
    log.warn("Unable to get the jail id for process %s." % pid)
  else:
    log.debug("get_bsd_jail_id(%s): jail ids do not exist on %s" % (pid, os_name))
  
  return 0

def expand_path(path, cwd = None):
  """
  Provides an absolute path, expanding tildes with the user's home and
  appending a current working directory if the path was relative.
  
  :param str path: path to be expanded
  :param str cwd: current working directory to expand relative paths with, our
    process' if this is **None**
  
  :returns: **str** of the path expanded to be an absolute path, never with an
    ending slash
  """
  
  if is_windows():
    relative_path = path.replace("/", "\\").rstrip("\\")
  else:
    relative_path = path.rstrip("/")
  
  if not relative_path or os.path.isabs(relative_path):
    # empty or already absolute - nothing to do
    pass
  elif relative_path.startswith("~"):
    # prefixed with a ~ or ~user entry
    relative_path = os.path.expanduser(relative_path)
  else:
    # relative path, expand with the cwd
    
    if not cwd:
      cwd = os.getcwd()
    
    # we'll be dealing with both "my/path/" and "./my/path" entries, so
    # cropping the later
    if relative_path.startswith("./") or relative_path.startswith(".\\"):
      relative_path = relative_path[2:]
    elif relative_path == ".":
      relative_path = ""
    
    if relative_path == "":
      relative_path = cwd
    else:
      relative_path = os.path.join(cwd, relative_path)
  
  return relative_path

def call(command, default = UNDEFINED):
  """
  Issues a command in a subprocess, blocking until completion and returning the
  results. This is not actually ran in a shell so pipes and other shell syntax
  are not permitted.
  
  :param str command: command to be issued
  :param object default: response if the query fails
  
  :returns: **list** with the lines of output from the command
  
  :raises: **OSError** if this fails and no default was provided
  """
  
  try:
    is_shell_command = command.split(" ")[0] in SHELL_COMMANDS
    
    start_time = time.time()
    stdout, stderr = subprocess.Popen(command.split(), stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = is_shell_command).communicate()
    stdout, stderr = stdout.strip(), stderr.strip()
    runtime = time.time() - start_time
    
    log.debug("System call: %s (runtime: %0.2f)" % (command, runtime))
    trace_prefix = "Received from system (%s)" % command
    
    if stdout and stderr:
      log.trace(trace_prefix + ", stdout:\n%s\nstderr:\n%s" % (stdout, stderr))
    elif stdout:
      log.trace(trace_prefix + ", stdout:\n%s" % stdout)
    elif stderr:
      log.trace(trace_prefix + ", stderr:\n%s" % stderr)
    
    if stdout:
      return stdout.splitlines()
    else:
      return []
  except OSError, exc:
    log.debug("System call (failed): %s (error: %s)" % (command, exc))
    
    if default != UNDEFINED:
      return default
    else:
      raise exc
