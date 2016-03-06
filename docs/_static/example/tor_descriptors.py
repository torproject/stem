import sys

import stem.descriptor.remote

from stem.util import str_tools

# provides a mapping of observed bandwidth to the relay nicknames
def get_bw_to_relay():
  bw_to_relay = {}

  try:
    for desc in stem.descriptor.remote.get_server_descriptors().run():
      if desc.exit_policy.is_exiting_allowed():
        bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
  except Exception as exc:
    print("Unable to retrieve the server descriptors: %s" % exc)

  return bw_to_relay

# prints the top fifteen relays

bw_to_relay = get_bw_to_relay()
count = 1

for bw_value in sorted(bw_to_relay.keys(), reverse = True):
  for nickname in bw_to_relay[bw_value]:
    print("%i. %s (%s/s)" % (count, nickname, str_tools.size_label(bw_value, 2)))
    count += 1

    if count > 15:
      sys.exit()
