from stem.descriptor import DocumentHandler
from stem.descriptor.remote import DescriptorDownloader

downloader = DescriptorDownloader()
consensus = downloader.get_consensus(document_handler = DocumentHandler.DOCUMENT).run()[0]

with open('/tmp/descriptor_dump', 'w') as descriptor_file:
  descriptor_file.write(str(consensus))
