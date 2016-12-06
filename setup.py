#!/usr/bin/env python
# Copyright 2012-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

import distutils.core
import os
import stem

DRY_RUN = True
SUMMARY = 'Stem is a Python controller library that allows applications to interact with Tor (https://www.torproject.org/).'
DRY_RUN_SUMMARY = 'Ignore this package. This is dry-run release creation to work around PyPI limitations (https://github.com/pypa/packaging-problems/issues/74#issuecomment-260716129).'

DESCRIPTION = """
For tutorials and API documentation see `stem's homepage <https://stem.torproject.org/>`_.

Quick Start
-----------

To install you can either use...

::

  pip install stem

... or install from the source tarball. Stem supports both the python 2.x and 3.x series. To use its python3 counterpart you simply need to install using that version of python.

::

  python3 setup.py install

After that, give some `tutorials <https://stem.torproject.org/tutorials.html>`_ a try! For questions or to discuss project ideas we're available on `irc <https://www.torproject.org/about/contact.html.en#irc>`_ and the `tor-dev@ email list <https://lists.torproject.org/cgi-bin/mailman/listinfo/tor-dev>`_.
""".strip()

MANIFEST = """
include cache_fallback_directories.py
include cache_manual.py
include LICENSE
include MANIFEST.in
include requirements.txt
include run_tests.py
include tox.ini
graft docs
graft test
global-exclude __pycache__
global-exclude *.orig
global-exclude *.pyc
global-exclude *.swp
global-exclude *.swo
global-exclude .tox
recursive-exclude test/data *
recursive-exclude docs/_build *
""".strip()

# Ensure this is our cwd, otherwise distutils fails with 'standard file
# 'setup.py' not found'.

os.chdir(os.path.dirname(os.path.abspath(__file__)))

with open('MANIFEST.in', 'w') as manifest_file:
  manifest_file.write(MANIFEST)

try:
  distutils.core.setup(
    name = 'stem-dry-run' if DRY_RUN else 'stem',
    version = stem.__version__,
    description = DRY_RUN_SUMMARY if DRY_RUN else SUMMARY,
    long_description = DESCRIPTION,
    license = stem.__license__,
    author = stem.__author__,
    author_email = stem.__contact__,
    url = stem.__url__,
    packages = ['stem', 'stem.descriptor', 'stem.interpreter', 'stem.response', 'stem.util'],
    keywords = 'tor onion controller',
    scripts = ['tor-prompt'],
    provides = ['stem'],
    package_data = {'stem': ['cached_tor_manual.cfg', 'settings.cfg'], 'stem.descriptor': ['fallback_directories.cfg'], 'stem.interpreter': ['settings.cfg'], 'stem.util': ['ports.cfg']},
    classifiers = [
      'Development Status :: 5 - Production/Stable',
      'Intended Audience :: Developers',
      'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
      'Topic :: Security',
      'Topic :: Software Development :: Libraries :: Python Modules',
    ],
  )
finally:
  if os.path.exists('MANIFEST.in'):
    os.remove('MANIFEST.in')

  if os.path.exists('MANIFEST'):
    os.remove('MANIFEST')
