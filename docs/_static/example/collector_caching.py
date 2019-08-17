import datetime
import stem.descriptor
import stem.descriptor.collector

yesterday = datetime.datetime.utcnow() - datetime.timedelta(days = 1)
cache_dir = '~/descriptor_cache/server_desc_today'

collector = stem.descriptor.collector.CollecTor()

for f in collector.files('server-descriptor', start = yesterday):
  f.download(cache_dir)

# then later...

for f in collector.files('server-descriptor', start = yesterday):
  for desc in f.read(cache_dir):
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))
