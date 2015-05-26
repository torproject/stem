from stem.descriptor import parse_file

server_descriptors = parse_file('/tmp/descriptor_dump', descriptor_type = 'server-descriptor 1.0')

for relay in server_descriptors:
  print(relay.fingerprint)
