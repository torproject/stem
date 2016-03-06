import stem.descriptor.remote

server_descriptors = stem.descriptor.remote.get_server_descriptors().run()

with open('/tmp/descriptor_dump', 'wb') as descriptor_file:
  descriptor_file.write(''.join(map(str, server_descriptors)))
