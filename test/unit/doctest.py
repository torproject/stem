"""
Tests examples from our documentation.
"""

from __future__ import absolute_import

import doctest
import os
import unittest

import stem.descriptor.router_status_entry
import stem.util.connection
import stem.util.str_tools
import stem.util.system
import stem.version

import test.mocking
import test.util

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

EXPECTED_CIRCUIT_STATUS = """\
20 EXTENDED $718BCEA286B531757ACAFF93AE04910EA73DE617=KsmoinOK,$649F2D0ACF418F7CFC6539AB2257EB2D5297BAFA=Eskimo BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2012-12-06T13:51:11.433755
19 BUILT $718BCEA286B531757ACAFF93AE04910EA73DE617=KsmoinOK,$30BAB8EE7606CBD12F3CC269AE976E0153E7A58D=Pascal1,$2765D8A8C4BBA3F89585A9FFE0E8575615880BEB=Anthracite PURPOSE=GENERAL TIME_CREATED=2012-12-06T13:50:56.969938\
"""

ADD_ONION_RESPONSE = """\
250-ServiceID=oekn5sqrvcu4wote
250-ClientAuth=bob:nKwfvVPmTNr2k2pG0pzV4g
250 OK
"""


class TestDocumentation(unittest.TestCase):
  def test_examples(self):
    stem_dir = os.path.join(test.util.STEM_BASE, 'stem')
    is_failed = False

    for path in stem.util.system.files_with_suffix(stem_dir, '.py'):
      args = {'module_relative': False}
      test_run = None

      if path.endswith('/stem/util/conf.py'):
        with patch('stem.util.conf.get_config') as get_config_mock:
          config = Mock()
          config.load.return_value = None
          get_config_mock.return_value = config

          test_run = doctest.testfile(path, **args)
      elif path.endswith('/stem/descriptor/router_status_entry.py'):
        args['globs'] = {
          '_base64_to_hex': stem.descriptor.router_status_entry._base64_to_hex,
        }

        test_run = doctest.testfile(path, **args)
      elif path.endswith('/stem/util/connection.py'):
        args['globs'] = {
          'expand_ipv6_address': stem.util.connection.expand_ipv6_address,
        }

        test_run = doctest.testfile(path, **args)
      elif path.endswith('/stem/util/str_tools.py'):
        args['globs'] = {
          '_to_camel_case': stem.util.str_tools._to_camel_case,
          'crop': stem.util.str_tools.crop,
          'size_label': stem.util.str_tools.size_label,
          'time_label': stem.util.str_tools.time_label,
          'time_labels': stem.util.str_tools.time_labels,
          'short_time_label': stem.util.str_tools.short_time_label,
          'parse_short_time_label': stem.util.str_tools.parse_short_time_label,
        }

        test_run = doctest.testfile(path, **args)
      elif path.endswith('/stem/response/__init__.py'):
        pass  # the escaped slashes seem to be confusing doctest
      elif path.endswith('/stem/control.py'):
        controller = Mock()
        controller.extend_circuit.side_effect = [19, 20]
        controller.get_info.side_effect = lambda arg: {
          'circuit-status': EXPECTED_CIRCUIT_STATUS,
        }[arg]

        response = test.mocking.get_message(ADD_ONION_RESPONSE)
        stem.response.convert('ADD_ONION', response)
        controller.create_ephemeral_hidden_service.return_value = response

        args['globs'] = {'controller': controller}
        test_run = doctest.testfile(path, **args)
      elif path.endswith('/stem/version.py'):
        with patch('stem.version.get_system_tor_version', Mock(return_value = stem.version.Version('0.2.1.30'))):
          test_run = doctest.testfile(path, **args)
      else:
        test_run = doctest.testfile(path, **args)

      if test_run and test_run.failed > 0:
        is_failed = True

    if is_failed:
      self.fail('doctests encountered errors')
