"""
Integ testing for the stem.manual module, fetching the latest man page from the
tor git repository and checking for new additions.
"""

import codecs
import os
import tempfile
import unittest

import stem.manual
import stem.util.system
import test.runner

from stem.manual import Category

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

EXPECTED_FILE_DESCRIPTION = 'Specify a new configuration file to contain further Tor configuration options OR pass - to make Tor read its configuration from standard input. (Default: @CONFDIR@/torrc, or $HOME/.torrc if that file is not found)'

EXPECTED_BANDWIDTH_RATE_DESCRIPTION = 'A token bucket limits the average incoming bandwidth usage on this node to the specified number of bytes per second, and the average outgoing bandwidth usage to that same value. If you want to run a relay in the public network, this needs to be at the very least 75 KBytes for a relay (that is, 600 kbits) or 50 KBytes for a bridge (400 kbits) - but of course, more is better; we recommend at least 250 KBytes (2 mbits) if possible. (Default: 1 GByte)\n\nWith this option, and in other options that take arguments in bytes, KBytes, and so on, other formats are also supported. Notably, "KBytes" can also be written as "kilobytes" or "kb"; "MBytes" can be written as "megabytes" or "MB"; "kbits" can be written as "kilobits"; and so forth. Tor also accepts "byte" and "bit" in the singular. The prefixes "tera" and "T" are also recognized. If no units are given, we default to bytes. To avoid confusion, we recommend writing "bytes" or "bits" explicitly, since it\'s easy to forget that "B" means bytes, not bits.'


class TestManual(unittest.TestCase):
  @classmethod
  def setUpClass(self):
    self.man_path = None
    self.man_content = None
    self.skip_reason = None
    self.download_error = None

    if stem.util.system.is_windows():
      self.skip_reason = '(unavailable on windows)'
    elif test.runner.Target.ONLINE not in test.runner.get_runner().attribute_targets:
      self.skip_reason = '(requires online target)'
    elif not stem.util.system.is_available('a2x'):
      self.skip_reason = '(requires asciidoc)'
    else:
      try:
        with tempfile.NamedTemporaryFile(prefix = 'tor_man_page.', delete = False) as tmp:
          stem.manual.download_man_page(file_handle = tmp)
          self.man_path = tmp.name

        self.man_content = stem.util.system.call('man -P cat %s' % self.man_path)
      except Exception as exc:
        self.download_error = 'Unable to download the man page: %s' % exc

  @classmethod
  def tearDownClass(self):
    if self.man_path and os.path.exists(self.man_path):
      os.remove(self.man_path)

  def requires_downloaded_manual(self):
    if self.skip_reason:
      test.runner.skip(self, self.skip_reason)
      return True
    elif self.download_error:
      self.fail(self.download_error)

    return False

  def test_get_categories(self):
    if self.requires_downloaded_manual():
      return

    categories = stem.manual._get_categories(self.man_content)

    present = set(categories.keys())
    missing_categories = present.difference(EXPECTED_CATEGORIES)
    extra_categories = EXPECTED_CATEGORIES.difference(present)

    if missing_categories:
      self.fail("Changed tor's man page? We expected the %s man page sections but they're no longer around, if expected then please update our test." % ', '.join(missing_categories))
    elif extra_categories:
      self.fail("Changed tor's man page? We weren't expecting the %s man page sections, if expected then please update our test." % ', '.join(extra_categories))

    self.assertEqual(['tor - The second-generation onion router'], categories['NAME'])
    self.assertEqual(['tor [OPTION value]...'], categories['SYNOPSIS'])
    self.assertEqual(8, len(categories['DESCRIPTION']))  # check parsing of multi-line entries

  def test_escapes_non_ascii(self):
    if self.requires_downloaded_manual():
      return

    def check(content):
      try:
        codecs.ascii_encode(content, 'strict')
      except UnicodeEncodeError as exc:
        self.fail("Unable to read '%s' as ascii: %s" % (content, exc))

    categories = stem.manual._get_categories(self.man_content)

    for category, lines in categories.items():
      check(category)

      for line in lines:
        check(line)

  def test_has_all_summaries(self):
    if self.requires_downloaded_manual():
      return

    manual = stem.manual.Manual.from_man(self.man_path)
    present = set(manual.config_options.keys())
    expected = set([key[15:] for key in stem.manual._config(lowercase = False) if key.startswith('manual.summary.')])

    # TODO: The 'Recognized' config name is due to our man page being slightly
    # malformed. Sending a tor patch later to fix it.

    missing_options = present.difference(expected).difference(set(['Recognized']))
    extra_options = expected.difference(present)

    if missing_options:
      self.fail("Changed tor's man page? Please update Stem's settings.cfg with summaries of the following config options: %s" % ', '.join(missing_options))
    elif extra_options:
      self.fail("Changed tor's man page? Please remove the following summaries from Stem's settings.cfg: %s" % ', '.join(extra_options))

  def test_attributes(self):
    if self.requires_downloaded_manual():
      return

    def assert_equal(category, expected, actual):
      if expected != actual:
        self.fail("Changed tor's man page? The %s changed as follows...\n\nexpected: %s\n\nactual: %s" % (category, expected, actual))

    manual = stem.manual.Manual.from_man(self.man_path)

    assert_equal('name', 'tor - The second-generation onion router', manual.name)
    assert_equal('synopsis', 'tor [OPTION value]...', manual.synopsis)
    assert_equal('description', EXPECTED_DESCRIPTION, manual.description)

    assert_equal('commandline options', EXPECTED_CLI_OPTIONS, set(manual.commandline_options.keys()))
    assert_equal('help option', 'Display a short help message and exit.', manual.commandline_options['-h, -help'])
    assert_equal('file option', EXPECTED_FILE_DESCRIPTION, manual.commandline_options['-f FILE'])

    assert_equal('signals', EXPECTED_SIGNALS, set(manual.signals.keys()))
    assert_equal('sighup description', 'Tor will catch this, clean up and sync to disk if necessary, and exit.', manual.signals['SIGTERM'])

    assert_equal('number of files', 31, len(manual.files))
    assert_equal('lib path description', 'The tor process stores keys and other data here.', manual.files['@LOCALSTATEDIR@/lib/tor/'])

    for category, expected_count in EXPECTED_OPTION_COUNTS.items():
      assert_equal('number of %s category entries' % category, expected_count, len([entry for entry in manual.config_options.values() if entry.category == category]))

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

    manual = stem.manual.Manual.from_man(os.path.join(os.path.dirname(__file__), 'tor.1_with_unknown'))

    self.assertEqual('tor - The second-generation onion router', manual.name)
    self.assertEqual('', manual.synopsis)
    self.assertEqual('', manual.description)
    self.assertEqual({}, manual.commandline_options)
    self.assertEqual({}, manual.signals)
    self.assertEqual({}, manual.files)

    self.assertEqual(2, len(manual.config_options))

    option = [entry for entry in manual.config_options.values() if entry.category == Category.UNKNOWN][0]
    self.assertEqual(Category.UNKNOWN, option.category)
    self.assertEqual('SpiffyNewOption', option.name)
    self.assertEqual('transport exec path-to-binary [options]', option.usage)
    self.assertEqual('', option.summary)
    self.assertEqual('Description of this new option.', option.description)
