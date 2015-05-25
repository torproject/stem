from stem.descriptor.remote import DescriptorDownloader

downloader = DescriptorDownloader()
server_descriptors = downloader.get_server_descriptors().run()

with open('/tmp/descriptor_dump', 'wb') as descriptor_file:
  descriptor_file.write(''.join(map(str, server_descriptors)))
