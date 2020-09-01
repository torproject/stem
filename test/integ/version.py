"""
Tests that the stem.version functions can handle the tor instance we're
running with.
"""

import unittest

import stem.version
import test.require
import test.runner
from stem.util.test_tools import async_test


class TestVersion(unittest.TestCase):
  @test.require.command('tor')
  def test_get_system_tor_version(self):
    """
    Basic verification checks for the get_system_tor_version() function.
    """

    # Since tor is in our path we should expect to be able to get the version
    # that way, though this might not belong to our test instance (if we're
    # running against a specific tor binary).

    stem.version.get_system_tor_version()

    # try running against a command that exists, but isn't tor
    self.assertRaises(OSError, stem.version.get_system_tor_version, 'ls')

    # try running against a command that doesn't exist
    self.assertRaises(OSError, stem.version.get_system_tor_version, 'blarg')

  @test.require.controller
  @async_test
  async def test_getinfo_version_parsing(self):
    """
    Issues a 'GETINFO version' query to our test instance and makes sure that
    we can parse it.
    """

    control_socket = await test.runner.get_runner().get_tor_socket()
    await control_socket.send('GETINFO version')
    version_response = await control_socket.recv()
    await control_socket.close()

    # the getinfo response looks like...
    # 250-version=0.2.3.10-alpha-dev (git-65420e4cb5edcd02)
    # 250 OK

    tor_version = list(version_response)[0]
    tor_version = tor_version[8:].split(' ', 1)[0]
    stem.version.Version(tor_version)
