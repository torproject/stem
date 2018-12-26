import sys

import stem.descriptor.remote
import stem.util.tor_tools


def download_descriptors(fingerprint):
  """
  Downloads the descriptors we need to validate this relay. Downloads are
  parallelized, providing the caller with a tuple of the form...

    (router_status_entry, server_descriptor, extrainfo_descriptor)
  """

  conensus_query = stem.descriptor.remote.get_consensus()
  server_desc_query = stem.descriptor.remote.get_server_descriptors(fingerprint)
  extrainfo_query = stem.descriptor.remote.get_extrainfo_descriptors(fingerprint)

  router_status_entries = filter(lambda desc: desc.fingerprint == fingerprint, conensus_query.run())

  if len(router_status_entries) != 1:
    raise IOError("Unable to find relay '%s' in the consensus" % fingerprint)

  return (
    router_status_entries[0],
    server_desc_query.run()[0],
    extrainfo_query.run()[0],
  )

if __name__ == '__main__':
  fingerprint = raw_input("What relay fingerprint would you like to validate?\n")
  print('')  # blank line

  if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
    print("'%s' is not a valid relay fingerprint" % fingerprint)
    sys.exit(1)

  try:
    router_status_entry, server_desc, extrainfo_desc = download_descriptors(fingerprint)
  except Exception as exc:
    print(exc)
    sys.exit(1)

  if router_status_entry.digest == server_desc.digest():
    print("Server descriptor digest is correct")
  else:
    print("Server descriptor digest invalid, expected %s but is %s" % (router_status_entry.digest, server_desc.digest()))

  if server_desc.extra_info_digest == extrainfo_desc.digest():
    print("Extrainfo descriptor digest is correct")
  else:
    print("Extrainfo descriptor digest invalid, expected %s but is %s" % (server_desc.extra_info_digest, extrainfo_desc.digest()))
