import argparse
import collections
import time

import stem.connection
import stem.util.system
import stem.util.str_tools

from stem.control import Listener
from stem.util.connection import get_connections, port_usage, is_valid_ipv4_address

HEADER_LINE = " {version}   uptime: {uptime}   flags: {flags}\n"

DIV = '+%s+%s+%s+' % ('-' * 30, '-' * 6, '-' * 6)
COLUMN = '| %-28s | %4s | %4s |'

INBOUND_ORPORT = 'Inbound to our ORPort'
INBOUND_DIRPORT = 'Inbound to our DirPort'
INBOUND_CONTROLPORT = 'Inbound to our ControlPort'

OUTBOUND_ORPORT = 'Outbound to a relay'
OUTBOUND_EXIT = 'Outbound exit traffic'
OUTBOUND_UNKNOWN = 'Outbound uncategorized'


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--ctrlport", help="default: 9051 or 9151")
  parser.add_argument("--resolver", help="default: autodetected")
  args = parser.parse_args()

  control_port = int(args.ctrlport) if args.ctrlport else 'default'
  controller = stem.connection.connect(control_port = ('127.0.0.1', control_port))

  if not controller:
    return

  desc = controller.get_network_status(default = None)
  pid = controller.get_pid()

  print(HEADER_LINE.format(
    version = str(controller.get_version()).split()[0],
    uptime = stem.util.str_tools.short_time_label(time.time() - stem.util.system.start_time(pid)),
    flags = ', '.join(desc.flags if desc else ['none']),
  ))

  policy = controller.get_exit_policy()
  relays = {}  # address => [orports...]

  for desc in controller.get_network_statuses():
    relays.setdefault(desc.address, []).append(desc.or_port)

  # categorize our connections

  categories = collections.OrderedDict((
    (INBOUND_ORPORT, []),
    (INBOUND_DIRPORT, []),
    (INBOUND_CONTROLPORT, []),
    (OUTBOUND_ORPORT, []),
    (OUTBOUND_EXIT, []),
    (OUTBOUND_UNKNOWN, []),
  ))

  exit_connections = {}  # port => [connections]

  for conn in get_connections(resolver = args.resolver, process_pid = pid):
    if conn.protocol == 'udp':
        continue

    if conn.local_port in controller.get_ports(Listener.OR, []):
      categories[INBOUND_ORPORT].append(conn)
    elif conn.local_port in controller.get_ports(Listener.DIR, []):
      categories[INBOUND_DIRPORT].append(conn)
    elif conn.local_port in controller.get_ports(Listener.CONTROL, []):
      categories[INBOUND_CONTROLPORT].append(conn)
    elif conn.remote_port in relays.get(conn.remote_address, []):
      categories[OUTBOUND_ORPORT].append(conn)
    elif policy.can_exit_to(conn.remote_address, conn.remote_port):
      categories[OUTBOUND_EXIT].append(conn)
      exit_connections.setdefault(conn.remote_port, []).append(conn)
    else:
      categories[OUTBOUND_UNKNOWN].append(conn)

  print(DIV)
  print(COLUMN % ('Type', 'IPv4', 'IPv6'))
  print(DIV)

  total_ipv4, total_ipv6 = 0, 0

  for label, connections in categories.items():
    if len(connections) == 0:
      continue

    ipv4_count = len([conn for conn in connections if is_valid_ipv4_address(conn.remote_address)])
    ipv6_count = len(connections) - ipv4_count

    total_ipv4, total_ipv6 = total_ipv4 + ipv4_count, total_ipv6 + ipv6_count
    print(COLUMN % (label, ipv4_count, ipv6_count))

  print(DIV)
  print(COLUMN % ('Total', total_ipv4, total_ipv6))
  print(DIV)
  print('')

  if exit_connections:
    print(DIV)
    print(COLUMN % ('Exit Port', 'IPv4', 'IPv6'))
    print(DIV)

    total_ipv4, total_ipv6 = 0, 0

    for port in sorted(exit_connections):
      connections = exit_connections[port]
      ipv4_count = len([conn for conn in connections if is_valid_ipv4_address(conn.remote_address)])
      ipv6_count = len(connections) - ipv4_count
      total_ipv4, total_ipv6 = total_ipv4 + ipv4_count, total_ipv6 + ipv6_count

      usage = port_usage(port)
      label = '%s (%s)' % (port, usage) if usage else port

      print(COLUMN % (label, ipv4_count, ipv6_count))

    print(DIV)
    print(COLUMN % ('Total', total_ipv4, total_ipv6))
    print(DIV)
    print('')


if __name__ == '__main__':
  main()
