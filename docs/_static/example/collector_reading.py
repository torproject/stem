import datetime
import stem.descriptor.collector

yesterday = datetime.datetime.utcnow() - datetime.timedelta(days = 1)

# provide yesterday's exits

for desc in stem.descriptor.collector.get_server_descriptors(start = yesterday):
  if desc.exit_policy.is_exiting_allowed():
    print('  %s (%s)' % (desc.nickname, desc.fingerprint))
