# Copyright 2011-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Tor versioning information and requirements for its features. These can be
easily parsed and compared, for instance...

::

  >>> from stem.version import get_system_tor_version, Requirement
  >>> my_version = get_system_tor_version()
  >>> print(my_version)
  0.2.1.30
  >>> my_version >= Requirement.DORMANT_MODE
  False

**Module Overview:**

::

  get_system_tor_version - gets the version of our system's tor installation

  Version - Tor versioning information

.. data:: Requirement (enum)

  Enumerations for the version requirements of features.

  ========================== ===========
  Requirement                Description
  ========================== ===========
  **DORMANT_MODE**           **DORMANT** and **ACTIVE** :data:`~stem.Signal`
  **DROPTIMEOUTS**           **DROPTIMEOUTS** controller command
  **HSFETCH_V3**             HSFETCH for version 3 hidden services
  **ONION_CLIENT_AUTH_ADD**  **ONION_CLIENT_AUTH_ADD** controller command
  **ONION_SERVICE_AUTH_ADD** For adding ClientAuthV3 to a v3 onion service via ADD_ONION
  ========================== ===========
"""

import functools
import os
import re

import stem.util
import stem.util.enum
import stem.util.system

from typing import Any, Callable

# cache for the get_system_tor_version function
VERSION_CACHE = {}

VERSION_PATTERN = re.compile(r'^([0-9]+)\.([0-9]+)\.([0-9]+)(\.[0-9]+)?(-\S*)?(( \(\S*\))*)$')


def get_system_tor_version(tor_cmd: str = 'tor') -> 'stem.version.Version':
  """
  Queries tor for its version. This is os dependent, only working on linux,
  osx, and bsd.

  :param tor_cmd: command used to run tor

  :returns: :class:`~stem.version.Version` provided by the tor command

  :raises: **OSError** if unable to query or parse the version
  """

  if tor_cmd not in VERSION_CACHE:
    version_cmd = '%s --version' % tor_cmd

    try:
      version_output = stem.util.system.call(version_cmd)
    except OSError as exc:
      # make the error message nicer if this is due to tor being unavialable

      if 'No such file or directory' in str(exc):
        if os.path.isabs(tor_cmd):
          raise OSError("Unable to check tor's version. '%s' doesn't exist." % tor_cmd)
        else:
          raise OSError("Unable to run '%s'. Maybe tor isn't in your PATH?" % version_cmd)

      raise OSError(exc)

    for line in version_output:
      # output example:
      # Oct 21 07:19:27.438 [notice] Tor v0.2.1.30. This is experimental software. Do not rely on it for strong anonymity. (Running on Linux i686)
      # Tor version 0.2.1.30.

      if line.startswith('Tor version ') and line.endswith('.'):
        try:
          version_str = line[12:-1]
          VERSION_CACHE[tor_cmd] = Version(version_str)
          break
        except ValueError as exc:
          raise OSError(exc)

    if tor_cmd not in VERSION_CACHE:
      raise OSError("'%s' didn't provide a parseable version:\n\n%s" % (version_cmd, '\n'.join(version_output)))

  return VERSION_CACHE[tor_cmd]


@functools.lru_cache()
def _get_version(version_str: str) -> 'stem.version.Version':
  return Version(version_str)


class Version(object):
  """
  Comparable tor version. These are constructed from strings that conform to
  the 'new' style in the `tor version-spec
  <https://gitweb.torproject.org/torspec.git/tree/version-spec.txt>`_,
  such as "0.1.4" or "0.2.2.23-alpha (git-7dcd105be34a4f44)".

  .. versionchanged:: 1.6.0
     Added all_extra parameter.

  :var int major: major version
  :var int minor: minor version
  :var int micro: micro version
  :var int patch: patch level (**None** if undefined)
  :var str status: status tag such as 'alpha' or 'beta-dev' (**None** if undefined)
  :var str extra: first extra information without its parentheses such as
    'git-8be6058d8f31e578' (**None** if undefined)
  :var list all_extra: all extra information entries, without their parentheses
  :var str git_commit: git commit id (**None** if it wasn't provided)

  :param version_str: version to be parsed

  :raises: **ValueError** if input isn't a valid tor version
  """

  def __init__(self, version_str: str) -> None:
    self.version_str = version_str
    version_parts = VERSION_PATTERN.match(version_str)

    if version_parts:
      major, minor, micro, patch_str, status, extra_str, _ = version_parts.groups()

      # The patch and status matches are optional (may be None) and have an extra
      # proceeding period or dash if they exist. Stripping those off.

      patch = int(patch_str[1:]) if patch_str else None

      if status:
        status = status[1:]

      self.major = int(major)
      self.minor = int(minor)
      self.micro = int(micro)
      self.patch = patch
      self.status = status
      self.all_extra = [entry[1:-1] for entry in extra_str.strip().split()] if extra_str else []
      self.extra = self.all_extra[0] if self.all_extra else None
      self.git_commit = None

      for extra in self.all_extra:
        if extra and re.match('^git-[0-9a-f]{16}$', extra):
          self.git_commit = extra[4:]
          break
    else:
      raise ValueError("'%s' isn't a properly formatted tor version" % version_str)

  def __str__(self) -> str:
    """
    Provides the string used to construct the version.
    """

    return self.version_str

  def _compare(self, other: Any, method: Callable[[Any, Any], bool]) -> bool:
    """
    Compares version ordering according to the spec.
    """

    if not isinstance(other, Version):
      return False

    for attr in ('major', 'minor', 'micro', 'patch'):
      my_version = getattr(self, attr)
      other_version = getattr(other, attr)

      if my_version is None:
        my_version = 0

      if other_version is None:
        other_version = 0

      if my_version != other_version:
        return method(my_version, other_version)

    # According to the version spec...
    #
    #   If we *do* encounter two versions that differ only by status tag, we
    #   compare them lexically as ASCII byte strings.

    my_status = self.status if self.status else ''
    other_status = other.status if other.status else ''

    return method(my_status, other_status)

  def __hash__(self) -> int:
    return stem.util._hash_attr(self, 'major', 'minor', 'micro', 'patch', 'status', cache = True)

  def __eq__(self, other: Any) -> bool:
    return self._compare(other, lambda s, o: s == o)

  def __ne__(self, other: Any) -> bool:
    return not self == other

  def __gt__(self, other: Any) -> bool:
    """
    Checks if this version meets the requirements for a given feature.
    """

    return self._compare(other, lambda s, o: s > o)

  def __ge__(self, other: Any) -> bool:
    return self._compare(other, lambda s, o: s >= o)


Requirement = stem.util.enum.Enum(
  ('DORMANT_MODE', Version('0.4.0.1-alpha')),
  ('DROPTIMEOUTS', Version('0.4.5.0-alpha')),
  ('HSFETCH_V3', Version('0.4.1.1-alpha')),
  ('ONION_CLIENT_AUTH_ADD', Version('0.4.3.1-alpha')),
  ('ONION_SERVICE_AUTH_ADD', Version('0.4.6.1-alpha')),
)
