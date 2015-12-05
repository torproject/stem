#!/usr/bin/env python
# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Caches tor's latest manual content. Run this to pick new man page changes.
"""

import os
import re
import sys

import stem.manual
import stem.util.system

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

CACHE_PATH = os.path.join(os.path.dirname(__file__), 'stem', 'cached_tor_manual')
GITWEB_MAN_LOG = 'https://gitweb.torproject.org/tor.git/log/doc/tor.1.txt'
MAN_LOG_LINK = "href='/tor.git/commit/doc/tor.1.txt\?id=([^']*)'"

if __name__ == '__main__':
  try:
    man_log_page = urllib.urlopen(GITWEB_MAN_LOG).read()
    man_commit = re.search(MAN_LOG_LINK, man_log_page).group(1)
  except:
    print "Unable to determine the latest commit to edit tor's man page: %s" % sys.exc_info()[1]
    sys.exit(1)

  try:
    stem_commit = stem.util.system.call('git rev-parse HEAD')[0]
  except IOError as exc:
    print "Unable to determine stem's current commit: %s" % exc
    sys.exit(1)

  print('Latest tor commit editing man page: %s' % man_commit)
  print('Current stem commit: %s' % stem_commit)
  print('')

  cached_manual = stem.manual.Manual.from_cache()
  latest_manual = stem.manual.Manual.from_remote()

  if cached_manual == latest_manual:
    print('Manual information is already up to date, nothing to do.')
    sys.exit(0)

  print('Differences detected...\n')

  for attr in ('name', 'synopsis', 'description', 'commandline_options', 'signals', 'files', 'config_options'):
    cached_attr = getattr(cached_manual, attr)
    latest_attr = getattr(latest_manual, attr)

    if cached_attr != latest_attr:
      print("* Manual's %s attribute changed\n" % attr)

      if attr in ('name', 'synopsis', 'description'):
        print('  Previously...\n\n%s\n' % cached_attr)
        print('  Updating to...\n\n%s' % latest_attr)
      else:
        added_items = set(latest_attr.items()).difference(cached_attr.items())
        removed_items = set(cached_attr.items()).difference(latest_attr.items())

        for added_item in added_items:
          print('  adding %s => %s' % added_item)

        for removed_item in removed_items:
          print('  removing %s => %s' % removed_item)

      print('\n')

  latest_manual.man_commit = man_commit
  latest_manual.stem_commit = stem_commit
  latest_manual.save(CACHE_PATH)
