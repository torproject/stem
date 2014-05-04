"""
Handles making requests and formatting the responses.
"""

import re

import stem
import stem.util.connection
import stem.util.tor_tools

from stem.interpretor import msg, uses_settings
from stem.util.term import Attr, Color, format

STANDARD_OUTPUT = (Color.BLUE, )
BOLD_OUTPUT = (Color.BLUE, Attr.BOLD)
ERROR_OUTPUT = (Attr.BOLD, Color.RED)

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache


@uses_settings
def help_output(controller, arg, config):
  """
  Provides our /help response.

  :param stem.Controller controller: tor control connection
  :param str arg: controller or interpretor command to provide help output for
  :param stem.util.conf.Config config: interpretor configuration

  :returns: **str** with our help response
  """

  # Normalizing inputs first so we can better cache responses.

  arg = arg.upper()

  # If there's multiple arguments then just take the first. This is
  # particularly likely if they're trying to query a full command (for
  # instance "/help GETINFO version")

  arg = arg.split(' ')[0]

  # strip slash if someone enters an interpretor command (ex. "/help /help")

  if arg.startswith('/'):
    arg = arg[1:]

  return _help_output(controller, arg, config)


@lru_cache()
def _help_output(controller, arg, config):
  if not arg:
    general_help = ''

    for line in msg('help.general').splitlines():
      cmd_start = line.find(' - ')

      if cmd_start != -1:
        general_help += format(line[:cmd_start], *BOLD_OUTPUT)
        general_help += format(line[cmd_start:] + '\n', *STANDARD_OUTPUT)
      else:
        general_help += format(line + '\n', *BOLD_OUTPUT)

    return general_help

  usage_info = config.get('help.usage', {})

  if not arg in usage_info:
    return format("No help information available for '%s'..." % arg, *ERROR_OUTPUT)

  output = format(usage_info[arg] + '\n', *BOLD_OUTPUT)

  description = config.get('help.description.%s' % arg.lower(), '')

  for line in description.splitlines():
    output += format('  ' + line + '\n', *STANDARD_OUTPUT)

  output += '\n'

  if arg == 'GETINFO':
    results = controller.get_info('info/names', None)

    if results:
      for line in results.splitlines():
        if ' -- ' in line:
          opt, summary = line.split(' -- ', 1)

          output += format("%-33s" % opt, *BOLD_OUTPUT)
          output += format(" - %s\n" % summary, *STANDARD_OUTPUT)
  elif arg == 'GETCONF':
    results = controller.get_info('config/names', None)

    if results:
      options = [opt.split(' ', 1)[0] for opt in results.splitlines()]

      for i in range(0, len(options), 2):
        line = ''

        for entry in options[i:i + 1]:
          line += '%-42s' % entry

        output += format(line + '\n', *STANDARD_OUTPUT)
  elif arg == 'SIGNAL':
    signal_options = config.get('help.signal.options', {})

    for signal, summary in signal_options.items():
      output += format('%-15s' % signal, *BOLD_OUTPUT)
      output += format(' - %s\n' % summary, *STANDARD_OUTPUT)
  elif arg == 'SETEVENTS':
    results = controller.get_info('events/names', None)

    if results:
      entries = results.split()

      # displays four columns of 20 characters

      for i in range(0, len(entries), 4):
        line = ''

        for entry in entries[i:i + 4]:
          line += '%-20s' % entry

        output += format(line + '\n', *STANDARD_OUTPUT)
  elif arg == 'USEFEATURE':
    results = controller.get_info('features/names', None)

    if results:
      output += format(results + '\n', *STANDARD_OUTPUT)
  elif arg in ('LOADCONF', 'POSTDESCRIPTOR'):
    # gives a warning that this option isn't yet implemented
    output += format(msg('msg.multiline_unimplemented_notice') + '\n', *ERROR_OUTPUT)

  return output


class ControlInterpretor(object):
  """
  Handles issuing requests and providing nicely formed responses, with support
  for special irc style subcommands.
  """

  def __init__(self, controller):
    self._controller = controller
    self._received_events = []

  def register_event(self, event):
    """
    Adds the event to our buffer so it'll be in '/events' output.
    """

    self._received_events.append(event)

  def do_help(self, arg):
    """
    Performs the '/help' operation, giving usage information for the given
    argument or a general summary if there wasn't one.
    """

    return help_output(self._controller, arg)

  def do_events(self, arg):
    """
    Performs the '/events' operation, dumping the events that we've received
    belonging to the given types. If no types are specified then this provides
    all buffered events.
    """

    events = self._received_events
    event_types = arg.upper().split()

    if event_types:
      events = filter(lambda event: event.type in event_types, events)

    return '\n'.join([format(str(event), *STANDARD_OUTPUT) for event in events])

  def do_info(self, arg):
    """
    Performs the '/info' operation, looking up a relay by fingerprint, IP
    address, or nickname and printing its descriptor and consensus entries in a
    pretty fashion.
    """

    output, fingerprint = '', None

    # determines the fingerprint, leaving it unset and adding an error message
    # if unsuccessful

    if not arg:
      # uses our fingerprint if we're a relay, otherwise gives an error

      fingerprint = self._controller.get_info('fingerprint', None)

      if not fingerprint:
        output += format("We aren't a relay, no information to provide", *ERROR_OUTPUT)
    elif stem.util.tor_tools.is_valid_fingerprint(arg):
      fingerprint = arg
    elif stem.util.tor_tools.is_valid_nickname(arg):
      desc = self._controller.get_network_status(arg, None)

      if desc:
        fingerprint = desc.fingerprint
      else:
        return format("Unable to find a relay with the nickname of '%s'" % arg, *ERROR_OUTPUT)
    elif ':' in arg or stem.util.connection.is_valid_ipv4_address(arg):
      # we got an address, so looking up the fingerprint

      if ':' in arg:
        address, port = arg.split(':', 1)

        if not stem.util.connection.is_valid_ipv4_address(address):
          return format("'%s' isn't a valid IPv4 address" % address, *ERROR_OUTPUT)
        elif port and not stem.util.connection.is_valid_port(port):
          return format("'%s' isn't a valid port" % port, *ERROR_OUTPUT)

        port = int(port)
      else:
        address, port = arg, None

      matches = {}

      for desc in self._controller.get_network_statuses():
        if desc.address == address:
          if not port or desc.or_port == port:
            matches[desc.or_port] = desc.fingerprint

      if len(matches) == 0:
        output += format('No relays found at %s' % arg, *ERROR_OUTPUT)
      elif len(matches) == 1:
        fingerprint = matches.values()[0]
      else:
        output += format("There's multiple relays at %s, include a port to specify which.\n\n" % arg, *ERROR_OUTPUT)

        for i, or_port in enumerate(matches):
          output += format("  %i. %s:%s, fingerprint: %s\n" % (i + 1, address, or_port, matches[or_port]), *ERROR_OUTPUT)
    else:
      return format("'%s' isn't a fingerprint, nickname, or IP address" % arg, *ERROR_OUTPUT)

    if fingerprint:
      micro_desc = self._controller.get_microdescriptor(fingerprint, None)
      server_desc = self._controller.get_server_descriptor(fingerprint, None)
      ns_desc = self._controller.get_network_status(fingerprint, None)

      # We'll mostly rely on the router status entry. Either the server
      # descriptor or microdescriptor will be missing, so we'll treat them as
      # being optional.

      if not ns_desc:
        return format("Unable to find consensus information for %s" % fingerprint, *ERROR_OUTPUT)

      locale = self._controller.get_info('ip-to-country/%s' % ns_desc.address, None)
      locale_label = ' (%s)' % locale if locale else ''

      if server_desc:
        exit_policy_label = server_desc.exit_policy.summary()
      elif micro_desc:
        exit_policy_label = micro_desc.exit_policy.summary()
      else:
        exit_policy_label = 'Unknown'

      output += '%s (%s)\n' % (ns_desc.nickname, fingerprint)

      output += format('address: ', *BOLD_OUTPUT)
      output += '%s:%s%s\n' % (ns_desc.address, ns_desc.or_port, locale_label)

      output += format('published: ', *BOLD_OUTPUT)
      output += ns_desc.published.strftime('%H:%M:%S %d/%m/%Y') + '\n'

      if server_desc:
        output += format('os: ', *BOLD_OUTPUT)
        output += server_desc.platform.decode('utf-8', 'replace') + '\n'

        output += format('version: ', *BOLD_OUTPUT)
        output += str(server_desc.tor_version) + '\n'

      output += format('flags: ', *BOLD_OUTPUT)
      output += ', '.join(ns_desc.flags) + '\n'

      output += format('exit policy: ', *BOLD_OUTPUT)
      output += exit_policy_label + '\n'

      if server_desc:
        contact = server_desc.contact

        # clears up some highly common obscuring

        for alias in (' at ', ' AT '):
          contact = contact.replace(alias, '@')

        for alias in (' dot ', ' DOT '):
          contact = contact.replace(alias, '.')

        output += format('contact: ', *BOLD_OUTPUT)
        output += contact + '\n'

    return output.strip()

  def run_command(self, command):
    """
    Runs the given command. Requests starting with a '/' are special commands
    to the interpretor, and anything else is sent to the control port.

    :param stem.control.Controller controller: tor control connection
    :param str command: command to be processed

    :returns: **list** out output lines, each line being a list of
      (msg, format) tuples

    :raises: **stem.SocketClosed** if the control connection has been severed
    """

    if not self._controller.is_alive():
      raise stem.SocketClosed()

    command = command.strip()

    # Commands fall into three categories:
    #
    # * Interpretor commands. These start with a '/'.
    #
    # * Controller commands stem knows how to handle. We use our Controller's
    #   methods for these to take advantage of caching and present nicer
    #   output.
    #
    # * Other tor commands. We pass these directly on to the control port.

    if ' ' in command:
      cmd, arg = command.split(' ', 1)
    else:
      cmd, arg = command, ''

    output = ''

    if cmd.startswith('/'):
      if cmd == '/quit':
        raise stem.SocketClosed()
      elif cmd == '/events':
        output = self.do_events(arg)
      elif cmd == '/info':
        output = self.do_info(arg)
      elif cmd == '/help':
        output = self.do_help(arg)
      else:
        output = format("'%s' isn't a recognized command" % command, *ERROR_OUTPUT)

      output += '\n'  # give ourselves an extra line before the next prompt
    else:
      cmd = cmd.upper()  # makes commands uppercase to match the spec

      if cmd == 'GETINFO':
        try:
          response = self._controller.get_info(arg.split())
          output = format('\n'.join(response.values()), *STANDARD_OUTPUT)
        except stem.ControllerError as exc:
          output = format(str(exc), *ERROR_OUTPUT)
      elif cmd in ('SETCONF', 'RESETCONF'):
        # arguments can either be '<param>', '<param>=<value>', or
        # '<param>="<value>"' entries

        param_list = []

        while arg:
          # TODO: I'm a little dubious of this for LineList values (like the
          # ExitPolicy) since they're parsed as a single value. However, tor
          # seems to be happy to get a single comma separated string (though it
          # echos back faithfully rather than being parsed) so leaving this
          # alone for now.

          quoted_match = re.match(r'^(\S+)=\"([^"]+)\"', arg)
          nonquoted_match = re.match(r'^(\S+)=(\S+)', arg)

          if quoted_match:
            # we're dealing with a '<param>="<value>"' entry
            param, value = quoted_match.groups()

            param_list.append((param, value))
            arg = arg[len(param) + len(value) + 3:].strip()
          elif nonquoted_match:
            # we're dealing with a '<param>=<value>' entry
            param, value = nonquoted_match.groups()

            param_list.append((param, value))
            arg = arg[len(param) + len(value) + 1:].strip()
          else:
            # starts with just a param
            param = arg.split()[0]
            param_list.append((param, None))
            arg = arg[len(param):].strip()

        try:
          is_reset = cmd == 'RESETCONF'
          self._controller.set_options(param_list, is_reset)
        except stem.ControllerError as exc:
          output = format(str(exc), *ERROR_OUTPUT)
      elif cmd == 'SETEVENTS':
        try:
          # first discontinue listening to prior events

          self._controller.remove_event_listener(self.register_event)

          # attach listeners for the given group of events

          if arg:
            events = arg.split()
            self._controller.add_event_listener(self.register_event, *events)
            output = format('Listing for %s events\n' % ', '.join(events), *STANDARD_OUTPUT)
          else:
            output = format('Disabled event listening\n', *STANDARD_OUTPUT)
        except stem.ControllerError as exc:
          output = format(str(exc), *ERROR_OUTPUT)
      elif cmd.replace('+', '') in ('LOADCONF', 'POSTDESCRIPTOR'):
        # provides a notice that multi-line controller input isn't yet implemented
        output = format(msg('msg.multiline_unimplemented_notice'), *ERROR_OUTPUT)
      else:
        try:
          response = self._controller.msg(command)

          if cmd == 'QUIT':
            raise stem.SocketClosed()

          output = format(str(response), *STANDARD_OUTPUT)
        except stem.ControllerError as exc:
          if isinstance(exc, stem.SocketClosed):
            raise exc
          else:
            output = format(str(exc), *ERROR_OUTPUT)

    return output
