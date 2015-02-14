#!/usr/bin/env python
# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

# We cannot import anything from the stem module since this would risk
# importing code that does not work under python 3 *without* being converted.
#
# I hate to do this, but reading our module file's information directly.

import os
import re
from distutils.core import setup

STAT_LINE = re.compile(r"^__(.+)__ = '(.+)'$")

DESCRIPTION = """\
Stem is a Python controller library that allows applications to interact with
Tor <https://www.torproject.org/>."""

def get_module_info():
  # reads the basic __stat__ strings from our module's init

  result = {}
  cwd = os.path.sep.join(__file__.split(os.path.sep)[:-1])

  with open(os.path.join(cwd, 'stem', '__init__.py')) as init_file:
    for line in init_file.readlines():
      line_match = STAT_LINE.match(line)

      if line_match:
        keyword, value = line_match.groups()
        result[keyword] = value

  return result

module_info = get_module_info()

setup(
  name = 'stem',
  version = module_info['version'],
  description = DESCRIPTION,
  license = module_info['license'],
  author = module_info['author'],
  author_email = module_info['contact'],
  url = module_info['url'],
  packages = ['stem', 'stem.descriptor', 'stem.interpreter', 'stem.response', 'stem.util'],
  provides = ['stem'],
  keywords = 'tor onion controller',
  scripts = ['tor-prompt'],
  package_data = {'stem.interpreter': ['settings.cfg'], 'stem.util': ['ports.cfg']},
)

