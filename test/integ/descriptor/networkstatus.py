"""
Integration tests for stem.descriptor.networkstatus.
"""

import os
import unittest

import stem
import stem.descriptor
import stem.descriptor.networkstatus
import stem.version
import test.runner

from test.runner import only_run_once

from test.util import register_new_capability


class TestNetworkStatus(unittest.TestCase):
  @only_run_once
  def test_cached_consensus(self):
    """
    Parses the cached-consensus file in our data directory.
    """

    consensus_path = test.runner.get_runner().get_test_dir('cached-consensus')

    if not os.path.exists(consensus_path):
      test.runner.skip(self, '(no cached-consensus)')
      return
    elif stem.util.system.is_windows():
      # Unable to check memory usage on windows, so can't prevent hanging the
      # system if things go bad.

      test.runner.skip(self, '(unavailable on windows)')
      return

    count = 0
    with open(consensus_path, 'rb') as descriptor_file:
      for router in stem.descriptor.parse_file(descriptor_file, 'network-status-consensus-3 1.0', validate = True):
        count += 1

        # check if there's any unknown flags and report them to the user
        for flag in router.flags:
          if flag not in stem.Flag:
            register_new_capability(flag, 'Network Flag')

        unrecognized_lines = router.get_unrecognized_lines()

        if unrecognized_lines:
          # Forward-compability:
          # 1) SHOULD function at least as it does normally (ignore the unknown)
          # 2) Report each of the aditional (unrecognized) fields to the user

          for line in unrecognized_lines:
            key = line.split()[0]
            register_new_capability(key, 'Network Descriptor Entry')

    # Sanity test that there's at least a hundred relays. If that's not the
    # case then this probably isn't a real, complete tor consensus.

    self.assertTrue(count > 100)

  @only_run_once
  def test_cached_microdesc_consensus(self):
    """
    Parses the cached-microdesc-consensus file in our data directory.
    """

    consensus_path = test.runner.get_runner().get_test_dir('cached-microdesc-consensus')

    if not os.path.exists(consensus_path):
      test.runner.skip(self, '(no cached-microdesc-consensus)')
      return
    elif stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return

    count = 0
    with open(consensus_path, 'rb') as descriptor_file:
      for router in stem.descriptor.parse_file(descriptor_file, 'network-status-microdesc-consensus-3 1.0', validate = True):
        count += 1

        # check if there's any unknown flags and report them to the user
        for flag in router.flags:
          if flag not in stem.Flag:
            register_new_capability(flag, 'Network Flag')

        unrecognized_lines = router.get_unrecognized_lines()

        if unrecognized_lines:
          # Forward-compability:
          # 1) SHOULD function at least as it does normally (ignore the unknown)
          # 2) Report each of the aditional (unrecognized) fields to the user

          for line in unrecognized_lines:
            key = line.split()[0]
            register_new_capability(key, 'Network Descriptor Entry')

    self.assertTrue(count > 100)
