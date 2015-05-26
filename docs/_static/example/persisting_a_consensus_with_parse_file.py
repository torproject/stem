from stem.descriptor import DocumentHandler, parse_file

consensus = next(parse_file(
  '/tmp/descriptor_dump',
  descriptor_type = 'network-status-consensus-3 1.0',
  document_handler = DocumentHandler.DOCUMENT,
))

for fingerprint, relay in consensus.routers.items():
  print("%s: %s" % (fingerprint, relay.nickname))
