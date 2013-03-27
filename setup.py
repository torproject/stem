#!/usr/bin/env python
# Copyright 2012-2013, Damian Johnson
# See LICENSE for licensing information

# We cannot import anything from the stem module since this would risk
# importing code that does not work under python 3 *without* being converted.
#
# I hate to do this, but reading our module file's information directly.

import os
import re
from distutils.core import setup

STAT_LINE = re.compile(r"^__(.+)__ = '(.+)'$")

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

DESCRIPTION = """\
Stem is a python controller library for Tor <https://www.torproject.org/>.
Like its predecessor, TorCtl, it uses Tor's control protocol to help
developers program against the Tor process."""

try:
  from distutils.command.build_py import build_py_2to3 as build_py
except ImportError:
  from distutils.command.build_py import build_py

setup(name = 'stem',
      version = module_info['version'],
      description = DESCRIPTION,
      license = module_info['license'],
      author = module_info['author'],
      author_email = module_info['contact'],
      url = module_info['url'],
      packages = ['stem', 'stem.descriptor', 'stem.response', 'stem.util'],
      provides = ['stem'],
      cmdclass = {'build_py': build_py},
      keywords = "tor onion controller",
)

