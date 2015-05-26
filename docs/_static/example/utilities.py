import sys

from stem.util.connection import get_connections, system_resolvers
from stem.util.system import pid_by_name

resolvers = system_resolvers()

if not resolvers:
  print("Stem doesn't support any connection resolvers on our platform.")
  sys.exit(1)

picked_resolver = resolvers[0]  # lets just opt for the first
print("Our platform supports connection resolution via: %s (picked %s)" % (', '.join(resolvers), picked_resolver))

tor_pids = pid_by_name('tor', multiple = True)

if not tor_pids:
  print("Unable to get tor's pid. Is it running?")
  sys.exit(1)
elif len(tor_pids) > 1:
  print("You're running %i instances of tor, picking the one with pid %i" % (len(tor_pids), tor_pids[0]))
else:
  print("Tor is running with pid %i" % tor_pids[0])

print("\nConnections:\n")

for conn in get_connections(picked_resolver, process_pid = tor_pids[0], process_name = 'tor'):
  print("  %s:%s => %s:%s" % (conn.local_address, conn.local_port, conn.remote_address, conn.remote_port))
