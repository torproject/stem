from stem.descriptor.remote import DescriptorDownloader
from stem.version import Version

downloader = DescriptorDownloader()
count, with_contact = 0, 0

print("Checking for outdated relays...")
print("")

for desc in downloader.get_server_descriptors():
  if desc.tor_version < Version('0.2.3.0'):
    count += 1

    if desc.contact:
      print('  %-15s %s' % (desc.tor_version, desc.contact.decode("utf-8", "replace")))
      with_contact += 1

print("")
print("%i outdated relays found, %i had contact information" % (count, with_contact))
