"""
Exercise the code in our examples directory.
"""

import importlib
import io
import os
import sys
import unittest

import stem.util.system
import test

from stem.descriptor.bandwidth_file import BandwidthFile
from unittest.mock import patch

EXAMPLE_DIR = os.path.join(test.STEM_BASE, 'docs', '_static', 'example')

EXPECTED_BANDWIDTH_STATS = """\
Relay FDCF49562E65B1CC219410009BD48A9EED387C77
  bw = 1
  bw_mean = 807445
  bw_median = 911047
  consensus_bandwidth = 1190000
  node_id = $FDCF49562E65B1CC219410009BD48A9EED387C77

Relay BD4172533C3F7271ABCCD9F057E06FD91547C42B
  bw = 1
  bw_mean = 631049
  bw_median = 622052
  consensus_bandwidth = 55000
  node_id = $BD4172533C3F7271ABCCD9F057E06FD91547C42B

"""

EXPECTED_BENCHMARK_SERVER_DESC_PREFIX = """\
Finished measure_average_advertised_bandwidth('%s')
  Total time: 0 seconds
  Processed server descriptors: 5
  Average advertised bandwidth: 313183
  Time per server descriptor:
""".rstrip()


def import_example(module_name):
  """
  Import this example module.
  """

  original_path = list(sys.path)
  sys.path.append(EXAMPLE_DIR)

  try:
    return importlib.import_module(module_name)
  finally:
    sys.path = original_path


class TestExamples(unittest.TestCase):
  def test_runs_everything(self):
    """
    Ensure we have tests for all our examples.
    """

    all_examples = set([os.path.basename(path)[:-3] for path in stem.util.system.files_with_suffix(EXAMPLE_DIR, '.py')])
    tested_examples = set([method[5:] for method in dir(self) if method.startswith('test_') and method != 'test_runs_everything'])

    extra = sorted(tested_examples.difference(all_examples))
    missing = sorted(all_examples.difference(tested_examples))

    if extra:
      self.fail("Changed our examples directory? We test the following which are not present: %s" % ', '.join(extra))

    if missing:
      self.fail("Changed our examples directory? The following are untested: %s" % ', '.join(missing))

  @patch('stem.descriptor.remote.get_bandwidth_file')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_bandwidth_stats(self, stdout_mock, get_bandwidth_file_mock):
    get_bandwidth_file_mock().run.return_value = [BandwidthFile.create({
      'content': [
        'bw=1 bw_mean=807445 bw_median=911047 consensus_bandwidth=1190000 node_id=$FDCF49562E65B1CC219410009BD48A9EED387C77',
        'bw=1 bw_mean=631049 bw_median=622052 consensus_bandwidth=55000 node_id=$BD4172533C3F7271ABCCD9F057E06FD91547C42B',
      ],
    })]

    import_example('bandwidth_stats')
    self.assertEqual(EXPECTED_BANDWIDTH_STATS, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = io.StringIO)
  def test_benchmark_server_descriptor_stem(self, stdout_mock):
    path = os.path.join(test.STEM_BASE, 'test', 'unit', 'descriptor', 'data', 'collector', 'server-descriptors-2005-12-cropped.tar')

    module = import_example('benchmark_server_descriptor_stem')
    module.measure_average_advertised_bandwidth(path)

    self.assertTrue(stdout_mock.getvalue().startswith(EXPECTED_BENCHMARK_SERVER_DESC_PREFIX % path))

  def test_benchmark_stem(self):
    pass

  def test_broken_listener(self):
    pass

  def test_check_digests(self):
    pass

  def test_client_usage_using_pycurl(self):
    pass

  def test_client_usage_using_socksipy(self):
    pass

  def test_collector_caching(self):
    pass

  def test_collector_reading(self):
    pass

  def test_compare_flags(self):
    pass

  def test_create_descriptor(self):
    pass

  def test_create_descriptor_content(self):
    pass

  def test_current_descriptors(self):
    pass

  def test_custom_path_selection(self):
    pass

  def test_descriptor_from_orport(self):
    pass

  def test_descriptor_from_tor_control_socket(self):
    pass

  def test_descriptor_from_tor_data_directory(self):
    pass

  def test_download_descriptor(self):
    pass

  def test_ephemeral_hidden_services(self):
    pass

  def test_event_listening(self):
    pass

  def test_exit_used(self):
    pass

  def test_fibonacci_multiprocessing(self):
    pass

  def test_fibonacci_threaded(self):
    pass

  def test_get_hidden_service_descriptor(self):
    pass

  def test_hello_world(self):
    pass

  def test_introduction_points(self):
    pass

  def test_list_circuits(self):
    pass

  def test_load_test(self):
    pass

  def test_manual_config_options(self):
    pass

  def test_outdated_relays(self):
    pass

  def test_persisting_a_consensus(self):
    pass

  def test_persisting_a_consensus_with_parse_file(self):
    pass

  def test_queue_listener(self):
    pass

  def test_read_with_parse_file(self):
    pass

  def test_reading_twitter(self):
    pass

  def test_relay_connections(self):
    pass

  def test_resuming_ephemeral_hidden_service(self):
    pass

  def test_running_hidden_service(self):
    pass

  def test_saving_and_loading_descriptors(self):
    pass

  def test_slow_listener(self):
    pass

  def test_tor_descriptors(self):
    pass

  def test_utilities(self):
    pass

  def test_validate_descriptor_content(self):
    pass

  def test_votes_by_bandwidth_authorities(self):
    pass

  def test_words_with(self):
    pass
