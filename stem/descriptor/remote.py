# Copyright 2013, Damian Johnson
# See LICENSE for licensing information

"""
Utilities for retrieving descriptors from directory authorities and mirrors.
This is mostly done through the
:class:`~stem.descriptor.remote.DescriptorDownloader` class, which issues the
requests and provides back parsed content. For example...

::

  downloader = DescriptorDownloader(
    cache = '/tmp/descriptor_cache',
    use_mirrors = True,
  )

  try:
    for desc in downloader.get_server_descriptors():
      if desc.exit_policy.is_exiting_allowed():
        print "%s (%s)" % (desc.nickname, desc.fingerprint)
  except IOError, exc:
    print "Unable to query the server descriptors: %s" % exc
"""

class DescriptorDownloader(object):
  pass
