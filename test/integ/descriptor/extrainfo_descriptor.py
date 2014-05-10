"""
Integration tests for stem.descriptor.extrainfo_descriptor.
"""

import datetime
import os
import unittest

import stem.descriptor
import test.runner

from stem.descriptor.extrainfo_descriptor import DirResponse
from test.integ.descriptor import get_resource


class TestExtraInfoDescriptor(unittest.TestCase):
  def test_metrics_relay_descriptor(self):
    """
    Parses and checks our results against an extrainfo descriptor from metrics.
    """

    descriptor_file = open(get_resource('extrainfo_relay_descriptor'), 'rb')

    expected_signature = """-----BEGIN SIGNATURE-----
K5FSywk7qvw/boA4DQcqkls6Ize5vcBYfhQ8JnOeRQC9+uDxbnpm3qaYN9jZ8myj
k0d2aofcVbHr4fPQOSST0LXDrhFl5Fqo5um296zpJGvRUeO6S44U/EfJAGShtqWw
7LZqklu+gVvhMKREpchVqlAwXkWR44VENm24Hs+mT3M=
-----END SIGNATURE-----"""

    desc = next(stem.descriptor.parse_file(descriptor_file, 'extra-info 1.0'))
    self.assertEquals('NINJA', desc.nickname)
    self.assertEquals('B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48', desc.fingerprint)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 3, 50), desc.published)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.read_history_end)
    self.assertEquals(900, desc.read_history_interval)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.write_history_end)
    self.assertEquals(900, desc.write_history_interval)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.dir_read_history_end)
    self.assertEquals(900, desc.dir_read_history_interval)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.dir_write_history_end)
    self.assertEquals(900, desc.dir_write_history_interval)
    self.assertEquals(expected_signature, desc.signature)
    self.assertEquals('00A57A9AAB5EA113898E2DD02A755E31AFC27227', desc.digest())
    self.assertEquals([], desc.get_unrecognized_lines())

    # The read-history, write-history, dirreq-read-history, and
    # dirreq-write-history lines are pretty long so just checking
    # the initial contents for the line and parsed values.

    read_values_start = [3309568, 9216, 41984, 27648, 123904]
    self.assertEquals(read_values_start, desc.read_history_values[:5])

    write_values_start = [1082368, 19456, 50176, 272384, 485376]
    self.assertEquals(write_values_start, desc.write_history_values[:5])

    dir_read_values_start = [0, 0, 0, 0, 33792, 27648, 48128]
    self.assertEquals(dir_read_values_start, desc.dir_read_history_values[:7])

    dir_write_values_start = [0, 0, 0, 227328, 349184, 382976, 738304]
    self.assertEquals(dir_write_values_start, desc.dir_write_history_values[:7])

  def test_metrics_bridge_descriptor(self):
    """
    Parses and checks our results against an extrainfo bridge descriptor from
    metrics.
    """

    descriptor_file = open(get_resource('extrainfo_bridge_descriptor'), 'rb')

    expected_dir_v2_responses = {
      DirResponse.OK: 0,
      DirResponse.UNAVAILABLE: 0,
      DirResponse.NOT_FOUND: 0,
      DirResponse.NOT_MODIFIED: 0,
      DirResponse.BUSY: 0,
    }

    expected_dir_v3_responses = {
      DirResponse.OK: 72,
      DirResponse.NOT_ENOUGH_SIGS: 0,
      DirResponse.UNAVAILABLE: 0,
      DirResponse.NOT_FOUND: 0,
      DirResponse.NOT_MODIFIED: 0,
      DirResponse.BUSY: 0,
    }

    desc = next(stem.descriptor.parse_file(descriptor_file, 'bridge-extra-info 1.0'))
    self.assertEquals('ec2bridgereaac65a3', desc.nickname)
    self.assertEquals('1EC248422B57D9C0BD751892FE787585407479A4', desc.fingerprint)
    self.assertEquals(datetime.datetime(2012, 6, 8, 2, 21, 27), desc.published)
    self.assertEquals(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.read_history_end)
    self.assertEquals(900, desc.read_history_interval)
    self.assertEquals(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.write_history_end)
    self.assertEquals(900, desc.write_history_interval)
    self.assertEquals(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.dir_read_history_end)
    self.assertEquals(900, desc.dir_read_history_interval)
    self.assertEquals(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.dir_write_history_end)
    self.assertEquals(900, desc.dir_write_history_interval)
    self.assertEquals('00A2AECCEAD3FEE033CFE29893387143146728EC', desc.digest())
    self.assertEquals([], desc.get_unrecognized_lines())

    read_values_start = [337920, 437248, 3995648, 48726016]
    self.assertEquals(read_values_start, desc.read_history_values[:4])

    write_values_start = [343040, 991232, 5649408, 49548288]
    self.assertEquals(write_values_start, desc.write_history_values[:4])

    dir_read_values_start = [0, 71680, 99328, 25600]
    self.assertEquals(dir_read_values_start, desc.dir_read_history_values[:4])

    dir_write_values_start = [5120, 664576, 2419712, 578560]
    self.assertEquals(dir_write_values_start, desc.dir_write_history_values[:4])

    self.assertEquals({}, desc.dir_v2_requests)
    self.assertEquals({}, desc.dir_v3_requests)

    self.assertEquals(expected_dir_v2_responses, desc.dir_v2_responses)
    self.assertEquals(expected_dir_v3_responses, desc.dir_v3_responses)

    self.assertEquals({}, desc.dir_v2_responses_unknown)
    self.assertEquals({}, desc.dir_v2_responses_unknown)

  def test_cached_descriptor(self):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """

    # lengthy test and uneffected by targets, so only run once

    if test.runner.only_run_once(self, 'test_cached_descriptor'):
      return

    descriptor_path = test.runner.get_runner().get_test_dir('cached-extrainfo')

    if not os.path.exists(descriptor_path):
      test.runner.skip(self, '(no cached descriptors)')
      return

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'extra-info 1.0'):
        unrecognized_lines = desc.get_unrecognized_lines()

        if desc.dir_v2_responses_unknown:
          self.fail('Unrecognized statuses on dirreq-v2-resp lines: %s' % desc.dir_v2_responses_unknown)
        elif desc.dir_v3_responses_unknown:
          self.fail('Unrecognized statuses on dirreq-v3-resp lines: %s' % desc.dir_v3_responses_unknown)
        elif desc.dir_v2_direct_dl_unknown:
          self.fail('Unrecognized stats on dirreq-v2-direct-dl lines: %s' % desc.dir_v2_direct_dl_unknown)
        elif desc.dir_v3_direct_dl_unknown:
          self.fail('Unrecognized stats on dirreq-v3-direct-dl lines: %s' % desc.dir_v2_direct_dl_unknown)
        elif desc.dir_v2_tunneled_dl_unknown:
          self.fail('Unrecognized stats on dirreq-v2-tunneled-dl lines: %s' % desc.dir_v2_tunneled_dl_unknown)
        elif unrecognized_lines:
          # TODO: This isn't actually a problem, and rather than failing we
          # should alert the user about these entries at the end of the tests
          # (along with new events, getinfo options, and such). For now though
          # there doesn't seem to be anything in practice to trigger this so
          # failing to get our attention if it does.

          self.fail('Unrecognized descriptor content: %s' % unrecognized_lines)
