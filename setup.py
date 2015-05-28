#!/usr/bin/env python
# Copyright 2012-2015, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import distutils.core
import stem


distutils.core.setup(
  name = 'stem',
  version = stem.__version__,
  description = 'Controller library for interacting with Tor <https://www.torproject.org/>',
  license = stem.__license__,
  author = stem.__author__,
  author_email = stem.__contact__,
  url = stem.__url__,
  packages = ['stem', 'stem.descriptor', 'stem.interpreter', 'stem.response', 'stem.util'],
  keywords = 'tor onion controller',
  scripts = ['tor-prompt'],
  package_data = {'stem.interpreter': ['settings.cfg'], 'stem.util': ['ports.cfg']},
)

