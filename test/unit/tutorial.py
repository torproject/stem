"""
Tests for the examples given in stem's tutorial.
"""

import io
import unittest

import stem.descriptor.remote

from stem.control import Controller
from stem.descriptor.reader import DescriptorReader
from stem.descriptor.server_descriptor import RelayDescriptor
from test import mocking
from test.unit import exec_documentation_example

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch


OVER_THE_RIVER_OUTPUT = """\
 * Connecting to tor
 * Creating our hidden service in /home/atagar/.tor/hello_world
 * Our service is available at uxiuaxejc3sxrb6i.onion, press ctrl+c to quit
 * Shutting down our hidden service
"""

MIRROR_MIRROR_OUTPUT = """\
1. speedyexit (102.13 KB/s)
2. speedyexit (102.13 KB/s)
3. speedyexit (102.13 KB/s)
"""


class TestTutorial(unittest.TestCase):
  def tearDown(self):
    # Ensure we don't cache a Mock object as our downloader. Otherwise future
    # tests will understandably be very sad. :P

    stem.descriptor.remote.SINGLETON_DOWNLOADER = None

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_the_little_relay_that_could(self, from_port_mock, stdout_mock):
    controller = from_port_mock().__enter__()
    controller.get_info.side_effect = lambda arg: {
      'traffic/read': '33406',
      'traffic/written': '29649',
    }[arg]

    exec_documentation_example('hello_world.py')
    self.assertEqual('My Tor relay has read 33406 bytes and written 29649.\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('shutil.rmtree')
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_over_the_river(self, from_port_mock, rmtree_mock, stdout_mock):
    def tutorial_example(app):
      import os
      import shutil

      from stem.control import Controller

      @app.route('/')
      def index():
        return '<h1>Hi Grandma!</h1>'

      print(' * Connecting to tor')

      with Controller.from_port() as controller:
        controller.authenticate()

        # All hidden services have a directory on disk. Lets put ours in tor's data
        # directory.

        hidden_service_dir = os.path.join(controller.get_conf('DataDirectory', '/tmp'), 'hello_world')

        # Create a hidden service where visitors of port 80 get redirected to local
        # port 5000 (this is where flask runs by default).

        print(' * Creating our hidden service in %s' % hidden_service_dir)
        result = controller.create_hidden_service(hidden_service_dir, 80, target_port = 5000)

        # The hostname is only available we can read the hidden service directory.
        # This requires us to be running with the same user as tor.

        if result.hostname:
          print(' * Our service is available at %s, press ctrl+c to quit' % result.hostname)
        else:
          print(" * Unable to determine our service's hostname, probably due to being unable to read the hidden service directory")

        try:
          app.run()
        finally:
          # Shut down the hidden service and clean it off disk. Note that you *don't*
          # want to delete the hidden service directory if you'd like to have this
          # same *.onion address in the future.

          print(' * Shutting down our hidden service')
          controller.remove_hidden_service(hidden_service_dir)
          shutil.rmtree(hidden_service_dir)

    flask_mock = Mock()

    hidden_service_data = Mock()
    hidden_service_data.hostname = 'uxiuaxejc3sxrb6i.onion'

    controller = from_port_mock().__enter__()
    controller.get_conf.return_value = '/home/atagar/.tor'
    controller.create_hidden_service.return_value = hidden_service_data

    tutorial_example(flask_mock)

    controller.get_conf.assert_called_once_with('DataDirectory', '/tmp')
    controller.create_hidden_service.assert_called_once_with('/home/atagar/.tor/hello_world', 80, target_port = 5000)
    rmtree_mock.assert_called_once_with('/home/atagar/.tor/hello_world')

    self.assertEqual(OVER_THE_RIVER_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.remote.DescriptorDownloader')
  def test_mirror_mirror_on_the_wall_1(self, downloader_mock, stdout_mock):
    downloader_mock().get_consensus().run.return_value = [mocking.get_router_status_entry_v2()]

    exec_documentation_example('current_descriptors.py')
    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_mirror_mirror_on_the_wall_2(self, from_port_mock, stdout_mock):
    controller = from_port_mock().__enter__()
    controller.get_network_statuses.return_value = [mocking.get_router_status_entry_v2()]

    exec_documentation_example('descriptor_from_tor_control_socket.py')
    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('%s.open' % __name__, create = True)
  def test_mirror_mirror_on_the_wall_3(self, open_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor import parse_file

      for desc in parse_file(open('/home/atagar/.tor/cached-consensus')):
        print('found relay %s (%s)' % (desc.nickname, desc.fingerprint))

    test_file = io.BytesIO(mocking.get_network_status_document_v3(
      routers = [mocking.get_router_status_entry_v3()],
      content = True,
    ))

    test_file.name = '/home/atagar/.tor/cached-consensus'
    open_mock.return_value = test_file

    tutorial_example()
    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.reader.DescriptorReader', spec = DescriptorReader)
  def test_mirror_mirror_on_the_wall_4(self, reader_mock, stdout_mock):
    reader = reader_mock().__enter__()
    reader.__iter__.return_value = iter([mocking.get_relay_server_descriptor()])

    exec_documentation_example('past_descriptors.py')
    self.assertEqual('found relay caerSidi (None)\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.remote.DescriptorDownloader')
  @patch('stem.prereq.is_crypto_available', Mock(return_value = False))
  def test_mirror_mirror_on_the_wall_5(self, downloader_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor.remote import DescriptorDownloader
      from stem.util import str_tools

      # provides a mapping of observed bandwidth to the relay nicknames
      def get_bw_to_relay():
        bw_to_relay = {}

        downloader = DescriptorDownloader()

        try:
          for desc in downloader.get_server_descriptors().run():
            if desc.exit_policy.is_exiting_allowed():
              bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
        except Exception as exc:
          print('Unable to retrieve the server descriptors: %s' % exc)

        return bw_to_relay

      # prints the top fifteen relays

      bw_to_relay = get_bw_to_relay()
      count = 1

      for bw_value in sorted(bw_to_relay.keys(), reverse = True):
        for nickname in bw_to_relay[bw_value]:
          print('%i. %s (%s/s)' % (count, nickname, str_tools.size_label(bw_value, 2)))
          count += 1

          if count > 15:
            return

    exit_descriptor = mocking.get_relay_server_descriptor({
      'router': 'speedyexit 149.255.97.109 9001 0 0'
    }, content = True).replace(b'reject *:*', b'accept *:*')

    exit_descriptor = mocking.sign_descriptor_content(exit_descriptor)
    exit_descriptor = RelayDescriptor(exit_descriptor)

    downloader_mock().get_server_descriptors().run.return_value = [
      exit_descriptor,
      mocking.get_relay_server_descriptor(),  # non-exit
      exit_descriptor,
      exit_descriptor,
    ]

    tutorial_example()
    self.assertEqual(MIRROR_MIRROR_OUTPUT, stdout_mock.getvalue())
