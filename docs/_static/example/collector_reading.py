import datetime
import stem.descriptor.collector

yesterday = datetime.datetime.utcnow() - datetime.timedelta(days = 1)

# provide yesterday's exits

exits = {}

for desc in stem.descriptor.collector.get_server_descriptors(start = yesterday):
  if desc.exit_policy.is_exiting_allowed():
    exits[desc.fingerprint] = desc

print('%i relays published an exiting policy today...\n' % len(exits))

for fingerprint, desc in exits.items():
  print('  %s (%s)' % (desc.nickname, fingerprint))
