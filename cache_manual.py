#!/usr/bin/env python
# Copyright 2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Caches tor's latest manual content. Run this to pick new man page changes.
"""

import os
import sys

import stem.manual

CACHE_PATH = os.path.join(os.path.dirname(__file__), 'stem', 'cached_tor_manual')

if __name__ == '__main__':
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

  latest_manual.save(CACHE_PATH)
