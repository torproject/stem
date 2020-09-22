"""
Exercise the code in our examples directory.
"""

import importlib
import io
import os
import sys
import unittest

import stem.socket
import stem.util.system
import test

from stem.control import Controller
from stem.descriptor.bandwidth_file import BandwidthFile
from stem.response import ControlMessage
from unittest.mock import Mock, patch

EXAMPLE_DIR = os.path.join(test.STEM_BASE, 'docs', '_static', 'example')
DESC_DIR = os.path.join(test.STEM_BASE, 'test', 'unit', 'descriptor', 'data')

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

EXPECTED_SERVER_DESC_BENCHMARK_PREFIX = """\
Finished measure_average_advertised_bandwidth('%s')
  Total time: 0 seconds
  Processed server descriptors: 5
  Average advertised bandwidth: 313183
  Time per server descriptor:
""".rstrip()

EXPECTED_EXTRAINFO_BENCHMARK_PREFIX = """\
Finished measure_countries_v3_requests('%s')
  Total time: 0 seconds
  Processed extrainfo descriptors: 7
  Number of countries: 6
  Time per extrainfo descriptor:
""".rstrip()

EXPECTED_CONSENSUS_BENCHMARK_PREFIX = """\
Finished measure_average_relays_exit('%s')
  Total time: 0 seconds
  Processed 2 consensuses with 243 router status entries
  Total exits: 28 (0.12%%)
  Time per consensus:
""".rstrip()

EXPECTED_MICRODESC_BENCHMARK_PREFIX = """\
Finished measure_fraction_relays_exit_80_microdescriptors('%s')
  Total time: 0 seconds
  Processed microdescriptors: 3
  Total exits to port 80: 1 (0.33%%)
  Time per microdescriptor:
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
    path = os.path.join(DESC_DIR, 'collector', 'server-descriptors-2005-12-cropped.tar')
    expected_prefix = EXPECTED_SERVER_DESC_BENCHMARK_PREFIX % path

    module = import_example('benchmark_server_descriptor_stem')
    module.measure_average_advertised_bandwidth(path)

    self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

  def test_benchmark_stem(self):
    module = import_example('benchmark_stem')

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'server-descriptors-2005-12-cropped.tar')
      expected_prefix = EXPECTED_SERVER_DESC_BENCHMARK_PREFIX % path

      module.measure_average_advertised_bandwidth(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'extra-infos-2019-04-cropped.tar')
      expected_prefix = EXPECTED_EXTRAINFO_BENCHMARK_PREFIX % path

      module.measure_countries_v3_requests(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'consensuses-2018-06-cropped.tar')
      expected_prefix = EXPECTED_CONSENSUS_BENCHMARK_PREFIX % path

      module.measure_average_relays_exit(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'microdescs-2019-05-cropped.tar')
      expected_prefix = EXPECTED_MICRODESC_BENCHMARK_PREFIX % path

      module.measure_fraction_relays_exit_80_microdescriptors(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

  @patch('time.sleep')
  @patch('stem.control.Controller.authenticate', Mock())
  @patch('stem.control.Controller.is_alive', Mock(return_value = True))
  @patch('stem.control.Controller.from_port')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_broken_listener(self, stdout_mock, from_port_mock, sleep_mock):
    controller = Controller(stem.socket.ControlSocket())
    from_port_mock.return_value = controller

    # emits a BW event when the example runs time.sleep()

    bw_event = ControlMessage.from_str('650 BW 15 25', 'EVENT', normalize = True)
    sleep_mock.side_effect = lambda duration: controller._handle_event(bw_event)

    import_example('broken_listener')

    self.assertEqual('start of broken_handler\n', stdout_mock.getvalue())

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
