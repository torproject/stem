from stem.descriptor import parse_file

for desc in parse_file('/home/atagar/.tor/cached-consensus'):
  print('found relay %s (%s)' % (desc.nickname, desc.fingerprint))
