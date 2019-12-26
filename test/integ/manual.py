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
import test
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
  'DENIAL OF SERVICE MITIGATION OPTIONS',
  'CLIENT AUTHORIZATION',
  'TESTING NETWORK OPTIONS',
  'NON-PERSISTENT OPTIONS',
  'SIGNALS',
  'FILES',
  'SEE ALSO',
  'BUGS',
  'AUTHORS',
])

EXPECTED_CLI_OPTIONS = set(['-f FILE', '--hash-password PASSWORD', '--ignore-missing-torrc', '--defaults-torrc FILE', '--key-expiration [purpose]', '--list-fingerprint', '--list-deprecated-options', '--allow-missing-torrc', '--nt-service', '--verify-config', '--dump-config short|full|non-builtin', '--service remove|start|stop', '--passphrase-fd FILEDES', '--keygen [--newpass]', '--list-torrc-options', '--service install [--options command-line options]', '--list-modules', '--quiet|--hush', '--version', '-h, --help'])
EXPECTED_SIGNALS = set(['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGUSR1', 'SIGUSR2', 'SIGCHLD', 'SIGPIPE', 'SIGXFSZ'])

EXPECTED_DESCRIPTION = """
Tor is a connection-oriented anonymizing communication service. Users choose a source-routed path through a set of nodes, and negotiate a "virtual circuit" through the network. Each node in a virtual circuit knows its predecessor and successor nodes, but no other nodes. Traffic flowing down the circuit is unwrapped by a symmetric key at each node, which reveals the downstream node.

Basically, Tor provides a distributed network of servers or relays ("onion routers"). Users bounce their TCP streams, including web traffic, ftp, ssh, etc., around the network, so that recipients, observers, and even the relays themselves have difficulty tracking the source of the stream.

    Note
    By default, tor acts as a client only. To help the network by providing bandwidth as a relay, change the ORPort configuration option as mentioned below. Please also consult the documentation on the Tor Project's website.
""".strip()

EXPECTED_FILE_DESCRIPTION = 'Specify a new configuration file to contain further Tor configuration options, or pass - to make Tor read its configuration from standard input. (Default: @CONFDIR@/torrc, or $HOME/.torrc if that file is not found)'

EXPECTED_BANDWIDTH_RATE_DESCRIPTION = 'A token bucket limits the average incoming bandwidth usage on this node to the specified number of bytes per second, and the average outgoing bandwidth usage to that same value. If you want to run a relay in the public network, this needs to be at the very least 75 KBytes for a relay (that is, 600 kbits) or 50 KBytes for a bridge (400 kbits) -- but of course, more is better; we recommend at least 250 KBytes (2 mbits) if possible. (Default: 1 GByte)\n\nNote that this option, and other bandwidth-limiting options, apply to TCP data only: They do not count TCP headers or DNS traffic.\n\nTor uses powers of two, not powers of ten, so 1 GByte is 1024*1024*1024 bytes as opposed to 1 billion bytes.\n\nWith this option, and in other options that take arguments in bytes, KBytes, and so on, other formats are also supported. Notably, "KBytes" can also be written as "kilobytes" or "kb"; "MBytes" can be written as "megabytes" or "MB"; "kbits" can be written as "kilobits"; and so forth. Case doesn\'t matter. Tor also accepts "byte" and "bit" in the singular. The prefixes "tera" and "T" are also recognized. If no units are given, we default to bytes. To avoid confusion, we recommend writing "bytes" or "bits" explicitly, since it\'s easy to forget that "B" means bytes, not bits.'

EXPECTED_EXIT_POLICY_DESCRIPTION_START = 'Set an exit policy for this server. Each policy'
EXPECTED_EXIT_POLICY_DESCRIPTION_END = 'it applies to both IPv4 and IPv6 addresses.'


class TestManual(unittest.TestCase):
  # TODO: remove when dropping support for python 2.6
  skip_reason = 'setUpClass() unsupported in python 2.6'

  @classmethod
  def setUpClass(self):
    self.man_path = None
    self.man_content = None
    self.skip_reason = None
    self.download_error = None

    if stem.util.system.is_windows():
      self.skip_reason = '(unavailable on windows)'
    elif test.Target.ONLINE not in test.runner.get_runner().attribute_targets:
      self.skip_reason = '(requires online target)'
    elif not stem.util.system.is_available('a2x'):
      self.skip_reason = '(requires asciidoc)'
    else:
      try:
        with tempfile.NamedTemporaryFile(prefix = 'tor_man_page.', delete = False) as tmp:
          stem.manual.download_man_page(file_handle = tmp)
          self.man_path = tmp.name

        man_cmd = 'man %s -P cat %s' % ('' if not stem.manual.HAS_ENCODING_ARG else '--encoding=ascii', self.man_path)
        self.man_content = stem.util.system.call(man_cmd, env = {'MANWIDTH': '10000000'})
      except Exception as exc:
        self.download_error = 'Unable to download the man page: %s' % exc

  @classmethod
  def tearDownClass(self):
    if self.man_path and os.path.exists(self.man_path):
      os.remove(self.man_path)

  def requires_downloaded_manual(self):
    if self.skip_reason:
      self.skipTest(self.skip_reason)
      return True
    elif self.download_error:
      self.fail(self.download_error)

    return False

  def test_escapes_non_ascii(self):
    """
    Check that our manual parser escapes all non-ascii characters. If this
    fails then that means someone probably added a new type of non-ascii
    character. Easy to fix: please simply add an escape for it in
    stem/manual.py's _get_categories().
    """

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

  def test_parsing_with_indented_lines(self):
    """
    Our ExitPolicy's description is an interesting one for our parser in that
    it has indented lines within it. Ensure we parse this correctly.
    """

    if self.requires_downloaded_manual():
      return

    manual = stem.manual.Manual.from_man(self.man_path)
    self.assertTrue(manual.config_options['ExitPolicy'].description.startswith(EXPECTED_EXIT_POLICY_DESCRIPTION_START))
    self.assertTrue(manual.config_options['ExitPolicy'].description.endswith(EXPECTED_EXIT_POLICY_DESCRIPTION_END))

  def test_that_cache_is_up_to_date(self):
    """
    Check if the cached manual information bundled with Stem is up to date or not.
    """

    if self.requires_downloaded_manual():
      return

    cached_manual = stem.manual.Manual.from_cache()
    latest_manual = stem.manual.Manual.from_man(self.man_path)

    if cached_manual != latest_manual:
      self.fail("Stem's cached manual information is out of date. Please run 'cache_manual.py'...\n\n%s" % stem.manual._manual_differences(cached_manual, latest_manual))

  def test_attributes(self):
    """
    General assertions against a few manual fields. If you update tor's manual
    then go ahead and simply update these assertions.
    """

    if self.requires_downloaded_manual():
      return

    def assert_equal(category, expected, actual):
      if expected != actual:
        if isinstance(expected, (set, tuple, list)):
          expected = sorted(expected)
          actual = sorted(actual)

        self.fail("Changed tor's man page? The %s changed as follows...\n\nexpected: %s\n\nactual: %s" % (category, expected, actual))

    manual = stem.manual.Manual.from_man(self.man_path)

    assert_equal('name', 'tor - The second-generation onion router', manual.name)
    assert_equal('synopsis', 'tor [OPTION value]...', manual.synopsis)
    assert_equal('description', EXPECTED_DESCRIPTION, manual.description)

    assert_equal('commandline options', EXPECTED_CLI_OPTIONS, set(manual.commandline_options.keys()))
    assert_equal('help option', 'Display a short help message and exit.', manual.commandline_options['-h, --help'])
    assert_equal('file option', EXPECTED_FILE_DESCRIPTION, manual.commandline_options['-f FILE'])

    assert_equal('signals', EXPECTED_SIGNALS, set(manual.signals.keys()))
    assert_equal('sighup description', 'Tor will catch this, clean up and sync to disk if necessary, and exit.', manual.signals['SIGTERM'])

    assert_equal('number of files', 47, len(manual.files))
    assert_equal('lib path description', 'The tor process stores keys and other data here.', manual.files['@LOCALSTATEDIR@/lib/tor/'])

    for category in Category:
      if len([entry for entry in manual.config_options.values() if entry.category == category]) == 0 and category != Category.UNKNOWN:
        self.fail('We had an empty %s section, did we intentionally drop it?' % category)

    unknown_options = [entry for entry in manual.config_options.values() if entry.category == Category.UNKNOWN]

    if unknown_options:
      self.fail("We don't recognize the category for the %s options. Maybe a new man page section? If so then please update the Category enum in stem/manual.py." % ', '.join([option.name for option in unknown_options]))

    option = manual.config_options['BandwidthRate']
    self.assertEqual(Category.GENERAL, option.category)
    self.assertEqual('BandwidthRate', option.name)
    self.assertEqual('N bytes|KBytes|MBytes|GBytes|TBytes|KBits|MBits|GBits|TBits', option.usage)
    self.assertEqual('Average bandwidth usage limit', option.summary)
    self.assertEqual(EXPECTED_BANDWIDTH_RATE_DESCRIPTION, option.description)

  def test_has_all_categories(self):
    """
    Check that the categories in tor's manual matches what we expect. If these
    change then we likely want to add/remove attributes from Stem's Manual
    class to match.
    """

    if self.requires_downloaded_manual():
      return

    categories = stem.manual._get_categories(self.man_content)

    present = set(categories.keys())
    missing_categories = EXPECTED_CATEGORIES.difference(present)
    extra_categories = present.difference(EXPECTED_CATEGORIES)

    if missing_categories:
      self.fail("Changed tor's man page? We expected the %s man page sections but they're no longer around. Might need to update our Manual class." % ', '.join(missing_categories))
    elif extra_categories:
      self.fail("Changed tor's man page? We weren't expecting the %s man page sections. Might need to update our Manual class." % ', '.join(extra_categories))

    self.assertEqual(['tor - The second-generation onion router'], categories['NAME'])
    self.assertEqual(['tor [OPTION value]...'], categories['SYNOPSIS'])

  def test_has_all_tor_config_options(self):
    """
    Check that all the configuration options tor supports are in the man page.
    """

    if self.requires_downloaded_manual():
      return

    with test.runner.get_runner().get_tor_controller() as controller:
      config_options_in_tor = set([line.split()[0] for line in controller.get_info('config/names').splitlines() if line.split()[1] != 'Virtual'])

      # options starting with an underscore are hidden by convention

      for name in list(config_options_in_tor):
        if name.startswith('_'):
          config_options_in_tor.remove(name)

    manual = stem.manual.Manual.from_man(self.man_path)
    config_options_in_manual = set(manual.config_options.keys())

    missing_from_manual = config_options_in_tor.difference(config_options_in_manual)

    if missing_from_manual:
      self.fail("The %s config options supported by tor isn't in its man page. Maybe we need to add them?" % ', '.join(missing_from_manual))

    extra_in_manual = config_options_in_manual.difference(config_options_in_tor)

    if extra_in_manual:
      self.fail("The %s config options in our man page aren't presently supported by tor. Are we using the latest git commit of tor? If so, maybe we need to remove them?" % ', '.join(extra_in_manual))
