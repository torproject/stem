#!/usr/bin/env python

from stem import __version__, \
                 __author__, \
                 __contact__, \
                 __url__, \
                 __license__

from distutils.core import setup

DESCRIPTION = """\
Stem is a python controller library for Tor <https://www.torproject.org/>.
Like its predecessor, TorCtl, it uses Tor's control protocol to help
developers program against the Tor process."""

try:
  from distutils.command.build_py import build_py_2to3 as build_py
except ImportError:
  from distutils.command.build_py import build_py

setup(name = 'stem',
      version = __version__,
      description = DESCRIPTION,
      license = __license__,
      author = __author__,
      author_email = __contact__,
      url = __url__,
      packages = ['stem', 'stem.descriptor', 'stem.response', 'stem.util'],
      provides = ['stem'],
      cmdclass = {'build_py': build_py},
      keywords = "tor onion controller",
)

