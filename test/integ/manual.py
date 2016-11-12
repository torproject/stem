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

EXPECTED_CLI_OPTIONS = set(['-f FILE', '--hash-password PASSWORD', '--ignore-missing-torrc', '--defaults-torrc FILE', '--list-fingerprint', '--list-deprecated-options', '--allow-missing-torrc', '--nt-service', '--verify-config', '--service remove|start|stop', '--passphrase-fd FILEDES', '--keygen [--newpass]', '--list-torrc-options', '--service install [--options command-line options]', '--quiet|--hush', '--version', '-h, -help'])
EXPECTED_SIGNALS = set(['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGUSR1', 'SIGUSR2', 'SIGCHLD', 'SIGPIPE', 'SIGXFSZ'])

EXPECTED_DESCRIPTION = """
Tor is a connection-oriented anonymizing communication service. Users choose a source-routed path through a set of nodes, and negotiate a "virtual circuit" through the network, in which each node knows its predecessor and successor, but no others. Traffic flowing down the circuit is unwrapped by a symmetric key at each node, which reveals the downstream node.

Basically, Tor provides a distributed network of servers or relays ("onion routers"). Users bounce their TCP streams -- web traffic, ftp, ssh, etc. -- around the network, and recipients, observers, and even the relays themselves have difficulty tracking the source of the stream.

By default, tor will act as a client only. To help the network by providing bandwidth as a relay, change the ORPort configuration option -- see below. Please also consult the documentation on the Tor Project's website.
""".strip()

EXPECTED_FILE_DESCRIPTION = 'Specify a new configuration file to contain further Tor configuration options OR pass - to make Tor read its configuration from standard input. (Default: @CONFDIR@/torrc, or $HOME/.torrc if that file is not found)'

EXPECTED_BANDWIDTH_RATE_DESCRIPTION = 'A token bucket limits the average incoming bandwidth usage on this node to the specified number of bytes per second, and the average outgoing bandwidth usage to that same value. If you want to run a relay in the public network, this needs to be at the very least 75 KBytes for a relay (that is, 600 kbits) or 50 KBytes for a bridge (400 kbits) -- but of course, more is better; we recommend at least 250 KBytes (2 mbits) if possible. (Default: 1 GByte)\n\nWith this option, and in other options that take arguments in bytes, KBytes, and so on, other formats are also supported. Notably, "KBytes" can also be written as "kilobytes" or "kb"; "MBytes" can be written as "megabytes" or "MB"; "kbits" can be written as "kilobits"; and so forth. Tor also accepts "byte" and "bit" in the singular. The prefixes "tera" and "T" are also recognized. If no units are given, we default to bytes. To avoid confusion, we recommend writing "bytes" or "bits" explicitly, since it\'s easy to forget that "B" means bytes, not bits.'


EXPECTED_EXIT_POLICY_DESCRIPTION = """
Set an exit policy for this server. Each policy is of the form "accept[6]|reject[6] ADDR[/MASK][:PORT]". If /MASK is omitted then this policy just applies to the host given. Instead of giving a host or network you can also use "*" to denote the universe (0.0.0.0/0 and ::/128), or *4 to denote all IPv4 addresses, and *6 to denote all IPv6 addresses.  PORT can be a single port number, an interval of ports "FROM_PORT-TO_PORT", or "*". If PORT is omitted, that means "*".

For example, "accept 18.7.22.69:*,reject 18.0.0.0/8:*,accept *:*" would reject any IPv4 traffic destined for MIT except for web.mit.edu, and accept any other IPv4 or IPv6 traffic.

Tor also allows IPv6 exit policy entries. For instance, "reject6 [FC00::]/7:*" rejects all destinations that share 7 most significant bit prefix with address FC00::. Respectively, "accept6 [C000::]/3:*" accepts all destinations that share 3 most significant bit prefix with address C000::.

accept6 and reject6 only produce IPv6 exit policy entries. Using an IPv4 address with accept6 or reject6 is ignored and generates a warning. accept/reject allows either IPv4 or IPv6 addresses. Use *4 as an IPv4 wildcard address, and *6 as an IPv6 wildcard address. accept/reject * expands to matching IPv4 and IPv6 wildcard address rules.

To specify all IPv4 and IPv6 internal and link-local networks (including 0.0.0.0/8, 169.254.0.0/16, 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, [::]/8, [FC00::]/7, [FE80::]/10, [FEC0::]/10, [FF00::]/8, and [::]/127), you can use the "private" alias instead of an address. ("private" always produces rules for IPv4 and IPv6 addresses, even when used with accept6/reject6.)

Private addresses are rejected by default (at the beginning of your exit policy), along with any configured primary public IPv4 and IPv6 addresses. These private addresses are rejected unless you set the ExitPolicyRejectPrivate config option to 0. For example, once you've done that, you could allow HTTP to 127.0.0.1 and block all other connections to internal networks with "accept 127.0.0.1:80,reject private:*", though that may also allow connections to your own computer that are addressed to its public (external) IP address. See RFC 1918 and RFC 3330 for more details about internal and reserved IP address space. See ExitPolicyRejectLocalInterfaces if you want to block every address on the relay, even those that aren't advertised in the descriptor.

This directive can be specified multiple times so you don't have to put it all on one line.

Policies are considered first to last, and the first match wins. If you want to allow the same ports on IPv4 and IPv6, write your rules using accept/reject *. If you want to allow different ports on IPv4 and IPv6, write your IPv6 rules using accept6/reject6 *6, and your IPv4 rules using accept/reject *4. If you want to _replace_ the default exit policy, end your exit policy with either a reject *:* or an accept *:*. Otherwise, you're _augmenting_ (prepending to) the default exit policy. The default exit policy is:

    reject *:25
    reject *:119
    reject *:135-139
    reject *:445
    reject *:563
    reject *:1214
    reject *:4661-4666
    reject *:6346-6429
    reject *:6699
    reject *:6881-6999
    accept *:*

    Since the default exit policy uses accept/reject *, it applies to both
    IPv4 and IPv6 addresses.
""".strip()


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
    elif test.runner.Target.ONLINE not in test.runner.get_runner().attribute_targets:
      self.skip_reason = '(requires online target)'
    elif not stem.util.system.is_available('a2x'):
      self.skip_reason = '(requires asciidoc)'
    else:
      try:
        with tempfile.NamedTemporaryFile(prefix = 'tor_man_page.', delete = False) as tmp:
          stem.manual.download_man_page(file_handle = tmp)
          self.man_path = tmp.name

        man_cmd = 'man %s -P cat %s' % ('' if stem.util.system.is_mac() else '--encoding=ascii', self.man_path)
        self.man_content = stem.util.system.call(man_cmd, env = {'MANWIDTH': '10000000'})
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
    self.assertEqual(EXPECTED_EXIT_POLICY_DESCRIPTION, manual.config_options['ExitPolicy'].description)

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

    assert_equal('number of files', 44, len(manual.files))
    assert_equal('lib path description', 'The tor process stores keys and other data here.', manual.files['@LOCALSTATEDIR@/lib/tor/'])

    for category in Category:
      if len([entry for entry in manual.config_options.values() if entry.category == category]) == 0 and category != Category.UNKNOWN:
        self.fail('We had an empty %s section, did we intentionally drop it?' % category)

    unknown_options = [entry for entry in manual.config_options.values() if entry.category == Category.UNKNOWN]

    if unknown_options:
      self.fail("We don't recognize the category for the %s options. Maybe a new man page section? If so then please update the Category enum in stem/manual.py." % ', '.join(unknown_options))

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
      config_options_in_tor = set([line.split()[0] for line in controller.get_info('config/names').splitlines()])

      # options starting with an underscore are hidden by convention

      for name in list(config_options_in_tor):
        if name.startswith('_'):
          config_options_in_tor.remove(name)

      # hidden service options are a special snowflake

      if 'HiddenServiceOptions' in config_options_in_tor:
        config_options_in_tor.remove('HiddenServiceOptions')

      # TODO: Looks like options we should remove from tor...
      #
      # https://trac.torproject.org/projects/tor/ticket/17665

      for option in ('SchedulerMaxFlushCells__', 'SchedulerLowWaterMark__', 'SchedulerHighWaterMark__'):
        if option in config_options_in_tor:
          config_options_in_tor.remove(option)

    manual = stem.manual.Manual.from_man(self.man_path)
    config_options_in_manual = set(manual.config_options.keys())

    missing_from_manual = config_options_in_tor.difference(config_options_in_manual)

    if missing_from_manual:
      self.fail("The %s config options supported by tor isn't in its man page. Maybe we need to add them?" % ', '.join(missing_from_manual))

    extra_in_manual = config_options_in_manual.difference(config_options_in_tor)

    if extra_in_manual:
      self.fail("The %s config options in our man page aren't presently supported by tor. Are we using the latest git commit of tor? If so, maybe we need to remove them?" % ', '.join(extra_in_manual))
