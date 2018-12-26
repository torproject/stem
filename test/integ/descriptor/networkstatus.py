"""
Integration tests for stem.descriptor.networkstatus.
"""

import os
import unittest

import stem
import stem.descriptor
import stem.descriptor.remote
import stem.util.test_tools
import stem.version
import test
import test.require
import test.runner

from stem.util.test_tools import asynchronous


class TestNetworkStatus(unittest.TestCase):
  @staticmethod
  def run_tests(args):
    stem.util.test_tools.ASYNC_TESTS['test.integ.descriptor.networkstatus.test_cached_consensus'].run(args.test_dir, threaded = True)
    stem.util.test_tools.ASYNC_TESTS['test.integ.descriptor.networkstatus.test_cached_microdesc_consensus'].run(args.test_dir, threaded = True)

  @test.require.only_run_once
  @test.require.online
  @test.require.cryptography
  def test_signature_validation(self):
    """
    The full consensus is pretty sizable so rather than storing a copy of it
    using the remote module. Chekcing the signature on the current consensus.
    """

    stem.descriptor.remote.get_consensus(document_handler = stem.descriptor.DocumentHandler.DOCUMENT, validate = True).run()

  @asynchronous
  def test_cached_consensus(test_dir):
    """
    Parses the cached-consensus file in our data directory.
    """

    consensus_path = os.path.join(test_dir, 'cached-consensus')

    if not os.path.exists(consensus_path):
      raise stem.util.test_tools.SkipTest('(no cached-consensus)')
    elif stem.util.system.is_windows():
      # Unable to check memory usage on windows, so can't prevent hanging the
      # system if things go bad.

      raise stem.util.test_tools.SkipTest('(unavailable on windows)')

    count, reported_flags = 0, []

    with open(consensus_path, 'rb') as descriptor_file:
      for router in stem.descriptor.parse_file(descriptor_file, 'network-status-consensus-3 1.0', validate = True):
        count += 1

        for flag in router.flags:
          if flag not in stem.Flag and flag not in reported_flags:
            test.register_new_capability('Flag (consensus)', flag)
            reported_flags.append(flag)

        for line in router.get_unrecognized_lines():
          test.register_new_capability('Consensus Line', line, suppression_token = line.split()[0])

    # Sanity test that there's at least a hundred relays. If that's not the
    # case then this probably isn't a real, complete tor consensus.

    if count < 100:
      raise AssertionError('%s only included %s relays' % (consensus_path, count))

  @asynchronous
  def test_cached_microdesc_consensus(test_dir):
    """
    Parses the cached-microdesc-consensus file in our data directory.
    """

    consensus_path = os.path.join(test_dir, 'cached-microdesc-consensus')

    if not os.path.exists(consensus_path):
      raise stem.util.test_tools.SkipTest('(no cached-microdesc-consensus)')
    elif stem.util.system.is_windows():
      raise stem.util.test_tools.SkipTest('(unavailable on windows)')

    count, reported_flags = 0, []

    with open(consensus_path, 'rb') as descriptor_file:
      for router in stem.descriptor.parse_file(descriptor_file, 'network-status-microdesc-consensus-3 1.0', validate = True):
        count += 1

        for flag in router.flags:
          if flag not in stem.Flag:
            test.register_new_capability('Flag (microdescriptor consensus)', flag)
            reported_flags.append(flag)

        for line in router.get_unrecognized_lines():
          test.register_new_capability('Microdescriptor Consensus Line', line, suppression_token = line.split()[0])

    if count < 100:
      raise AssertionError('%s only included %s relays' % (consensus_path, count))
