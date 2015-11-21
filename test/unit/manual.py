"""
Unit tessts for the stem.manual module. Test data comes from the following...

  * test/unit/tor.1 - Tor version 0.2.8.0-alpha-dev (git-3c6782395743a089)
"""

import codecs
import os
import unittest

import stem.manual
import stem.util.system
import test.runner

from stem.manual import Category

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache

TEST_MAN_PAGE = os.path.join(os.path.dirname(__file__), 'tor.1')

EXPECTED_CATEGORIES = set([
  'NAME',
  'SYNOPSIS',
  'DESCRIPTION',
  'COMMAND-LINE OPTIONS',
  'THE CONFIGURATION FILE FORMAT',
  'GENERAL OPTIONS',
  'CLIENT OPTIONS',
  'SERVER OPTIONS',
  'DIRECTORY SERVER OPTIONS',
  'DIRECTORY AUTHORITY SERVER OPTIONS',
  'HIDDEN SERVICE OPTIONS',
  'TESTING NETWORK OPTIONS',
  'SIGNALS',
  'FILES',
  'SEE ALSO',
  'BUGS',
  'AUTHORS',
])

EXPECTED_CLI_OPTIONS = set(['-h, -help', '-f FILE', '--allow-missing-torrc', '--defaults-torrc FILE', '--ignore-missing-torrc', '--hash-password PASSWORD', '--list-fingerprint', '--verify-config', '--service install [--options command-line options]', '--service remove|start|stop', '--nt-service', '--list-torrc-options', '--version', '--quiet|--hush'])
EXPECTED_SIGNALS = set(['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGUSR1', 'SIGUSR2', 'SIGCHLD', 'SIGPIPE', 'SIGXFSZ'])

EXPECTED_OPTION_COUNTS = {
  Category.GENERAL: 74,
  Category.CLIENT: 86,
  Category.RELAY: 47,
  Category.DIRECTORY: 5,
  Category.AUTHORITY: 34,
  Category.HIDDEN_SERVICE: 11,
  Category.TESTING: 32,
  Category.UNKNOWN: 0,
}

EXPECTED_DESCRIPTION = """
Tor is a connection-oriented anonymizing communication service. Users choose a source-routed path through a set of nodes, and negotiate a "virtual circuit" through the network, in which each node knows its predecessor and successor, but no others. Traffic flowing down the circuit is unwrapped by a symmetric key at each node, which reveals the downstream node.

Basically, Tor provides a distributed network of servers or relays ("onion routers"). Users bounce their TCP streams - web traffic, ftp, ssh, etc. - around the network, and recipients, observers, and even the relays themselves have difficulty tracking the source of the stream.

By default, tor will only act as a client only. To help the network by providing bandwidth as a relay, change the ORPort configuration option - see below. Please also consult the documentation on the Tor Project's website.
""".strip()

EXPECTED_FILE_DESCRIPTION = 'Specify a new configuration file to contain further Tor configuration options OR pass - to make Tor read its configuration from standard input. (Default: /usr/local/etc/tor/torrc, or $HOME/.torrc if that file is not found)'

EXPECTED_BANDWIDTH_RATE_DESCRIPTION = 'A token bucket limits the average incoming bandwidth usage on this node to the specified number of bytes per second, and the average outgoing bandwidth usage to that same value. If you want to run a relay in the public network, this needs to be at the very least 30 KBytes (that is, 30720 bytes). (Default: 1 GByte)\n\nWith this option, and in other options that take arguments in bytes, KBytes, and so on, other formats are also supported. Notably, "KBytes" can also be written as "kilobytes" or "kb"; "MBytes" can be written as "megabytes" or "MB"; "kbits" can be written as "kilobits"; and so forth. Tor also accepts "byte" and "bit" in the singular. The prefixes "tera" and "T" are also recognized. If no units are given, we default to bytes. To avoid confusion, we recommend writing "bytes" or "bits" explicitly, since it\'s easy to forget that "B" means bytes, not bits.'


@lru_cache()
def man_content():
  return stem.util.system.call('man -P cat %s' % TEST_MAN_PAGE)


class TestManual(unittest.TestCase):
  def test_is_important(self):
    self.assertTrue(stem.manual.is_important('ExitPolicy'))
    self.assertTrue(stem.manual.is_important('exitpolicy'))
    self.assertTrue(stem.manual.is_important('EXITPOLICY'))

    self.assertFalse(stem.manual.is_important('ConstrainedSockSize'))

  def test_get_categories(self):
    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return

    categories = stem.manual._get_categories(man_content())
    self.assertEqual(EXPECTED_CATEGORIES, set(categories.keys()))
    self.assertEqual(['tor - The second-generation onion router'], categories['NAME'])
    self.assertEqual(['tor [OPTION value]...'], categories['SYNOPSIS'])
    self.assertEqual(8, len(categories['DESCRIPTION']))  # check parsing of multi-line entries

  def test_escapes_non_ascii(self):
    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return

    def check(content):
      try:
        codecs.ascii_encode(content, 'strict')
      except UnicodeEncodeError as exc:
        self.fail("Unable to read '%s' as ascii: %s" % (content, exc))

    categories = stem.manual._get_categories(man_content())

    for category, lines in categories.items():
      check(category)

      for line in lines:
        check(line)

  def test_has_all_summaries(self):
    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return

    test.runner.skip(self, 'coming soon!')  # TODO: yup, got a few to fill in...

    manual = stem.manual.Manual.from_man(TEST_MAN_PAGE)
    missing_summary = []

    for config_option in manual.config_options.values():
      if not config_option.summary and config_option.category != Category.TESTING:
        missing_summary.append(config_option.name)

    if missing_summary:
      self.fail("The following config options are missing summaries: %s" % ', '.join(missing_summary))

  def test_attributes(self):
    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return

    manual = stem.manual.Manual.from_man(TEST_MAN_PAGE)

    self.assertEqual('tor - The second-generation onion router', manual.name)
    self.assertEqual('tor [OPTION value]...', manual.synopsis)
    self.assertEqual(EXPECTED_DESCRIPTION, manual.description)

    self.assertEqual(EXPECTED_CLI_OPTIONS, set(manual.commandline_options.keys()))
    self.assertEqual('Display a short help message and exit.', manual.commandline_options['-h, -help'])
    self.assertEqual(EXPECTED_FILE_DESCRIPTION, manual.commandline_options['-f FILE'])

    self.assertEqual(EXPECTED_SIGNALS, set(manual.signals.keys()))
    self.assertEqual('Tor will catch this, clean up and sync to disk if necessary, and exit.', manual.signals['SIGTERM'])

    self.assertEqual(31, len(manual.files))
    self.assertEqual('The tor process stores keys and other data here.', manual.files['/usr/local/var/lib/tor/'])

    for category, expected_count in EXPECTED_OPTION_COUNTS.items():
      self.assertEqual(expected_count, len([entry for entry in manual.config_options.values() if entry.category == category]))

    option = manual.config_options['BandwidthRate']
    self.assertEqual(Category.GENERAL, option.category)
    self.assertEqual('BandwidthRate', option.name)
    self.assertEqual('N bytes|KBytes|MBytes|GBytes|KBits|MBits|GBits', option.usage)
    self.assertEqual('Average bandwidth usage limit', option.summary)
    self.assertEqual(EXPECTED_BANDWIDTH_RATE_DESCRIPTION, option.description)

  def test_with_unknown_options(self):
    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return

    manual = stem.manual.Manual.from_man(TEST_MAN_PAGE + '_with_unknown')

    self.assertEqual('tor - The second-generation onion router', manual.name)
    self.assertEqual('', manual.synopsis)
    self.assertEqual('', manual.description)
    self.assertEqual({}, manual.commandline_options)
    self.assertEqual({}, manual.signals)

    self.assertEqual(2, len(manual.config_options))

    option = [entry for entry in manual.config_options.values() if entry.category == Category.UNKNOWN][0]
    self.assertEqual(Category.UNKNOWN, option.category)
    self.assertEqual('SpiffyNewOption', option.name)
    self.assertEqual('transport exec path-to-binary [options]', option.usage)
    self.assertEqual('', option.summary)
    self.assertEqual('Description of this new option.', option.description)
