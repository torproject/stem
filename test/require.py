# Copyright 2012-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Testing requirements. This provides annotations to skip tests that shouldn't be
run.

::

  Test Requirements
  |- only_run_once - skip test if it has been ran before
  |- needs - skips the test unless a requirement is met
  |
  |- cryptography - skips test unless the cryptography module is present
  |- command - requires a command to be on the path
  |- proc - requires the platform to have recognized /proc contents
  |
  |- controller - skips test unless tor provides a controller endpoint
  |- version - skips test unless we meet a tor version requirement
  |- ptrace - requires 'DisableDebuggerAttachment' to be set
  +- online - skips unless targets allow for online tests
"""

import importlib

import stem.util.system
import stem.version
import test
import test.runner

try:
  from cryptography.utils import int_to_bytes
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.backends.openssl.backend import backend
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  from cryptography.hazmat.primitives.serialization import load_der_public_key
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

  if not hasattr(rsa.RSAPrivateKey, 'sign') or not hasattr(backend, 'ed25519_supported') or not backend.ed25519_supported():
    raise ImportError()

  CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
  CRYPTOGRAPHY_AVAILABLE = False

RAN_TESTS = []


def only_run_once(func):
  """
  Skips the test if it has ran before. If it hasn't then flags it as being ran.
  This is useful to prevent lengthy tests that are independent of integ targets
  from being run repeatedly with ``RUN_ALL``.
  """

  def wrapped(self, *args, **kwargs):
    if self.id() not in RAN_TESTS:
      RAN_TESTS.append(self.id())
      return func(self, *args, **kwargs)
    else:
      self.skipTest('(already ran)')

  return wrapped


def needs(condition, message):
  """
  Skips the test unless the conditional evaluates to 'true'.
  """

  def decorator(func):
    def wrapped(self, *args, **kwargs):
      if condition():
        return func(self, *args, **kwargs)
      else:
        self.skipTest('(%s)' % message)

    return wrapped

  return decorator


def _can_access_controller():
  return test.runner.get_runner().is_accessible()


def _can_ptrace():
  return test.runner.Torrc.PTRACE in test.runner.get_runner().get_options()


def _is_online():
  return test.Target.ONLINE in test.runner.get_runner().attribute_targets


def command(cmd):
  """
  Skips the test unless a command is available on the path.
  """

  return needs(lambda: stem.util.system.is_available(cmd), '%s unavailable' % cmd)


def module(module_name):
  """
  Skip test unless this module is available.
  """

  try:
    importlib.import_module(module_name)
    available = True
  except:
    available = False

  return needs(lambda: available, '%s unavailable' % module_name)


def version(req_version):
  """
  Skips the test unless we meet the required version.

  :param stem.version.Version req_version: required tor version for the test
  """

  return needs(lambda: test.tor_version() >= req_version, 'requires %s' % req_version)


def version_older_than(req_version):
  """
  Skips the test unless we meet a version older than the requested version.

  :param stem.version.Version req_version: the version that tor should be older than
  """

  return needs(lambda: test.tor_version() < req_version, 'requires %s' % req_version)


cryptography = needs(lambda: CRYPTOGRAPHY_AVAILABLE, 'requires cryptography')
proc = needs(stem.util.proc.is_available, 'proc unavailable')
controller = needs(_can_access_controller, 'no connection')
ptrace = needs(_can_ptrace, 'DisableDebuggerAttachment is set')
online = needs(_is_online, 'requires online target')
