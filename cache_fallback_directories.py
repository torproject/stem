#!/usr/bin/env python
# Copyright 2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Caches tor's latest fallback directories.
"""

import re
import sys

import stem.descriptor.remote
import stem.util.conf
import stem.util.system

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

GITWEB_MAN_LOG = 'https://gitweb.torproject.org/tor.git/log/src/or/fallback_dirs.inc'
FALLBACK_DIR_LINK = "href='/tor.git/commit/src/or/fallback_dirs.inc\?id=([^']*)'"

if __name__ == '__main__':
  try:
    fallback_dir_page = urllib.urlopen(GITWEB_MAN_LOG).read()
    fallback_dir_commit = re.search(FALLBACK_DIR_LINK, fallback_dir_page).group(1)
  except:
    print("Unable to determine the latest commit to edit tor's fallback directories: %s" % sys.exc_info()[1])
    sys.exit(1)

  try:
    stem_commit = stem.util.system.call('git rev-parse HEAD')[0]
  except IOError as exc:
    print("Unable to determine stem's current commit: %s" % exc)
    sys.exit(1)

  print('Latest tor commit editing fallback directories: %s' % fallback_dir_commit)
  print('Current stem commit: %s' % stem_commit)
  print('')

  cached_fallback_directories = stem.descriptor.remote.FallbackDirectory.from_cache()
  latest_fallback_directories = stem.descriptor.remote.FallbackDirectory.from_remote()

  if cached_fallback_directories == latest_fallback_directories:
    print('Fallback directories are already up to date, nothing to do.')
    sys.exit(0)

  print('Differences detected...\n')
  print(stem.descriptor.remote._fallback_directory_differences(cached_fallback_directories, latest_fallback_directories))

  conf = stem.util.conf.Config()
  conf.set('tor_commit', fallback_dir_commit)
  conf.set('stem_commit', stem_commit)

  for directory in sorted(latest_fallback_directories.values(), lambda x, y: cmp(x.fingerprint, y.fingerprint)):
    fingerprint = directory.fingerprint
    conf.set('%s.address' % fingerprint, directory.address)
    conf.set('%s.or_port' % fingerprint, str(directory.or_port))
    conf.set('%s.dir_port' % fingerprint, str(directory.dir_port))

    if directory.orport_v6:
      conf.set('%s.orport6_address' % fingerprint, str(directory.orport_v6[0]))
      conf.set('%s.orport6_port' % fingerprint, str(directory.orport_v6[1]))

  conf.save(stem.descriptor.remote.CACHE_PATH)
