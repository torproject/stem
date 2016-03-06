import stem.descriptor.remote

try:
  for desc in stem.descriptor.remote.get_consensus().run():
    print("found relay %s (%s)" % (desc.nickname, desc.fingerprint))
except Exception as exc:
  print("Unable to retrieve the consensus: %s" % exc)
