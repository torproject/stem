#!/usr/bin/env python
# Copyright 2016-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Caches tor's latest fallback directories.
"""

import re
import sys
import json
import datetime
import urllib.request

import stem.directory
import stem.util.system

# call to GitLab API to retrieve file history
GITLAB_FALLBACK_LOG = 'https://gitlab.torproject.org/api/v4/projects/426/repository/files/src%2Fapp%2Fconfig%2Ffallback_dirs.inc/blame?ref=main'
# replace by function getting the right entry out of the JSON
FALLBACK_DIR_LINK = b"href='/tor.git/commit/src/app/config/fallback_dirs.inc\\?id=([^']*)'"

if __name__ == '__main__':
  try:
    fallback_dir_commit = sorted(
        json.loads(urllib.request.urlopen(GITLAB_FALLBACK_LOG).read()),
        key=lambda commit: datetime.datetime.fromisoformat(
            commit["commit"]["committed_date"]
        ),
        reverse=True,
    )[0]["commit"]["id"]
  except:
    print("Unable to determine the latest commit to edit tor's fallback directories: %s" % sys.exc_info()[1])
    sys.exit(1)

  try:
    stem_commit = stem.util.system.call('git rev-parse HEAD')[0]
  except OSError as exc:
    print("Unable to determine stem's current commit: %s" % exc)
    sys.exit(1)

  print('Latest tor commit editing fallback directories: %s' % fallback_dir_commit)
  print('Current stem commit: %s' % stem_commit)
  print('')

  cached_fallback_directories = stem.directory.Fallback.from_cache()
  latest_fallback_directories = stem.directory.Fallback.from_remote()

  if cached_fallback_directories == latest_fallback_directories:
    print('Fallback directories are already up to date, nothing to do.')
    sys.exit(0)

  # all fallbacks have the same header metadata, so just picking one

  headers = list(latest_fallback_directories.values())[0].header if latest_fallback_directories else None

  print('Differences detected...\n')
  print(stem.directory._fallback_directory_differences(cached_fallback_directories, latest_fallback_directories))
  stem.directory.Fallback._write(latest_fallback_directories, fallback_dir_commit, stem_commit, headers)
