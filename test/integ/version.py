"""
Tests that the stem.version functions can handle the tor instance we're
running with.
"""

import unittest

import stem.prereq
import stem.version
import test.runner

from test.runner import require_controller


class TestVersion(unittest.TestCase):
  def test_get_system_tor_version(self):
    """
    Basic verification checks for the get_system_tor_version() function.
    """

    if not stem.util.system.is_available('tor'):
      test.runner.skip(self, "(tor isn't in our path)")
      return

    # Since tor is in our path we should expect to be able to get the version
    # that way, though this might not belong to our test instance (if we're
    # running against a specific tor binary).

    stem.version.get_system_tor_version()

    # try running against a command that exists, but isn't tor
    self.assertRaises(IOError, stem.version.get_system_tor_version, 'ls')

    # try running against a command that doesn't exist
    self.assertRaises(IOError, stem.version.get_system_tor_version, 'blarg')

  @require_controller
  def test_get_system_tor_version_value(self):
    """
    Checks that the get_system_tor_version() provides the same value as our
    test instance provides.
    """

    runner = test.runner.get_runner()
    system_tor_version = stem.version.get_system_tor_version(runner.get_tor_command())
    self.assertEqual(runner.get_tor_version(), system_tor_version)

  @require_controller
  def test_getinfo_version_parsing(self):
    """
    Issues a 'GETINFO version' query to our test instance and makes sure that
    we can parse it.
    """

    control_socket = test.runner.get_runner().get_tor_socket()
    control_socket.send('GETINFO version')
    version_response = control_socket.recv()
    control_socket.close()

    # the getinfo response looks like...
    # 250-version=0.2.3.10-alpha-dev (git-65420e4cb5edcd02)
    # 250 OK

    tor_version = list(version_response)[0]
    tor_version = tor_version[8:].split(' ', 1)[0]
    stem.version.Version(tor_version)
