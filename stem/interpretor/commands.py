"""
Handles making requests and formatting the responses.
"""

import re

import stem
import stem.util.connection
import stem.util.tor_tools

from stem.interpretor import msg, uses_settings
from stem.util.term import Attr, Color, format

OUTPUT_FORMAT = (Color.BLUE, )
BOLD_OUTPUT_FORMAT = (Color.BLUE, Attr.BOLD)
ERROR_FORMAT = (Attr.BOLD, Color.RED)


class ControlInterpretor(object):
  """
  Handles issuing requests and providing nicely formed responses, with support
  for special irc style subcommands.
  """

  def __init__(self, controller):
    self.controller = controller
    self.received_events = []

  def register_event(self, event):
    """
    Adds the event to our buffer so it'll be in '/events' output.
    """

    self.received_events.append(event)

  @uses_settings
  def do_help(self, arg, config):
    """
    Performs the '/help' operation, giving usage information for the given
    argument or a general summary if there wasn't one.
    """

    arg = arg.upper()
    usage_info = config.get('help.usage', {})

    # If there's multiple arguments then just take the first. This is
    # particularly likely if they're trying to query a full command (for
    # instance "/help GETINFO version")

    arg = arg.split(' ')[0]

    # strip slash if someone enters an interpretor command (ex. "/help /help")

    if arg.startswith('/'):
      arg = arg[1:]

    output = ''

    if not arg:
      # provides the general help with everything bolded except descriptions

      for line in msg('help.general').splitlines():
        cmd_start = line.find(' - ')

        if cmd_start != -1:
          output += format(line[:cmd_start], *BOLD_OUTPUT_FORMAT)
          output += format(line[cmd_start:] + '\n', *OUTPUT_FORMAT)
        else:
          output += format(line + '\n', *BOLD_OUTPUT_FORMAT)
    elif arg in usage_info:
      # Provides information for the tor or interpretor argument. This bolds
      # the usage information and indents the description after it.

      usage = usage_info[arg]
      description = config.get('help.description.%s' % arg.lower(), '')

      output = format(usage + '\n', *BOLD_OUTPUT_FORMAT)

      for line in description.splitlines():
        output += format('  ' + line + '\n', *OUTPUT_FORMAT)

      if arg == 'GETINFO':
        # if this is the GETINFO option then also list the valid options

        info_options = self.controller.get_info('info/names', None)

        if info_options:
          for line in info_options.splitlines():
            line_match = re.match("^(.+) -- (.+)$", line)

            if line_match:
              opt, description = line_match.groups()

              output += format("%-33s" % opt, *BOLD_OUTPUT_FORMAT)
              output += format(" - %s\n" % description, *OUTPUT_FORMAT)
      elif arg == 'GETCONF':
        # lists all of the configuration options
        # TODO: integrate tor man page output when stem supports that

        conf_options = self.controller.get_info('config/names', None)

        if conf_options:
          conf_entries = [opt.split(' ', 1)[0] for opt in conf_options.split('\n')]

          # displays two columns of 42 characters

          for i in range(0, len(conf_entries), 2):
            line_entries = conf_entries[i:i + 2]

            line_content = ''

            for entry in line_entries:
              line_content += '%-42s' % entry

            output += format(line_content + '\n', *OUTPUT_FORMAT)

          output += format("For more information use '/help [CONFIG OPTION]'.", *BOLD_OUTPUT_FORMAT)
      elif arg == 'SIGNAL':
        # lists descriptions for all of the signals

        descriptions = config.get('help.signal.options', {})

        for signal, description in descriptions.items():
          output += format('%-15s' % signal, *BOLD_OUTPUT_FORMAT)
          output += format(' - %s\n' % description, *OUTPUT_FORMAT)
      elif arg == 'SETEVENTS':
        # lists all of the event types

        event_options = self.controller.get_info('events/names', None)

        if event_options:
          event_entries = event_options.split()

          # displays four columns of 20 characters

          for i in range(0, len(event_entries), 4):
            line_entries = event_entries[i:i + 4]

            line_content = ''

            for entry in line_entries:
              line_content += '%-20s' % entry

            output += format(line_content + '\n', *OUTPUT_FORMAT)
      elif arg == 'USEFEATURE':
        # lists the feature options

        feature_options = self.controller.get_info('features/names', None)

        if feature_options:
          output += format(feature_options + '\n', *OUTPUT_FORMAT)
      elif arg in ('LOADCONF', 'POSTDESCRIPTOR'):
        # gives a warning that this option isn't yet implemented
        output += format('\n' + msg('msg.multiline_unimplemented_notice') + '\n', *ERROR_FORMAT)
    else:
      output += format("No help information available for '%s'..." % arg, *ERROR_FORMAT)

    return output

  def do_events(self, arg):
    """
    Performs the '/events' operation, dumping the events that we've received
    belonging to the given types. If no types are specified then this provides
    all buffered events.
    """

    events = self.received_events
    event_types = arg.upper().split()

    if event_types:
      events = filter(lambda event: event.type in event_types, events)

    return '\n'.join([format(str(event), *OUTPUT_FORMAT) for event in events])

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

      fingerprint = self.controller.get_info('fingerprint', None)

      if not fingerprint:
        output += format("We aren't a relay, no information to provide", *ERROR_FORMAT)
    elif stem.util.tor_tools.is_valid_fingerprint(arg):
      fingerprint = arg
    elif stem.util.tor_tools.is_valid_nickname(arg):
      desc = self.controller.get_network_status(arg, None)

      if desc:
        fingerprint = desc.fingerprint
      else:
        return format("Unable to find a relay with the nickname of '%s'" % arg, *ERROR_FORMAT)
    elif ':' in arg or stem.util.connection.is_valid_ipv4_address(arg):
      # we got an address, so looking up the fingerprint

      if ':' in arg:
        address, port = arg.split(':', 1)

        if not stem.util.connection.is_valid_ipv4_address(address):
          return format("'%s' isn't a valid IPv4 address" % address, *ERROR_FORMAT)
        elif port and not stem.util.connection.is_valid_port(port):
          return format("'%s' isn't a valid port" % port, *ERROR_FORMAT)

        port = int(port)
      else:
        address, port = arg, None

      matches = {}

      for desc in self.controller.get_network_statuses():
        if desc.address == address:
          if not port or desc.or_port == port:
            matches[desc.or_port] = desc.fingerprint

      if len(matches) == 0:
        output += format('No relays found at %s' % arg, *ERROR_FORMAT)
      elif len(matches) == 1:
        fingerprint = matches.values()[0]
      else:
        output += format("There's multiple relays at %s, include a port to specify which.\n\n" % arg, *ERROR_FORMAT)

        for i, or_port in enumerate(matches):
          output += format("  %i. %s:%s, fingerprint: %s\n" % (i + 1, address, or_port, matches[or_port]), *ERROR_FORMAT)
    else:
      return format("'%s' isn't a fingerprint, nickname, or IP address" % arg, *ERROR_FORMAT)

    if fingerprint:
      micro_desc = self.controller.get_microdescriptor(fingerprint, None)
      server_desc = self.controller.get_server_descriptor(fingerprint, None)
      ns_desc = self.controller.get_network_status(fingerprint, None)

      # We'll mostly rely on the router status entry. Either the server
      # descriptor or microdescriptor will be missing, so we'll treat them as
      # being optional.

      if not ns_desc:
        return format("Unable to find consensus information for %s" % fingerprint, *ERROR_FORMAT)

      locale = self.controller.get_info('ip-to-country/%s' % ns_desc.address, None)
      locale_label = ' (%s)' % locale if locale else ''

      if server_desc:
        exit_policy_label = server_desc.exit_policy.summary()
      elif micro_desc:
        exit_policy_label = micro_desc.exit_policy.summary()
      else:
        exit_policy_label = 'Unknown'

      output += '%s (%s)\n' % (ns_desc.nickname, fingerprint)

      output += format('address: ', *BOLD_OUTPUT_FORMAT)
      output += '%s:%s%s\n' % (ns_desc.address, ns_desc.or_port, locale_label)

      output += format('published: ', *BOLD_OUTPUT_FORMAT)
      output += ns_desc.published.strftime('%H:%M:%S %d/%m/%Y') + '\n'

      if server_desc:
        output += format('os: ', *BOLD_OUTPUT_FORMAT)
        output += server_desc.platform.decode('utf-8', 'replace') + '\n'

        output += format('version: ', *BOLD_OUTPUT_FORMAT)
        output += str(server_desc.tor_version) + '\n'

      output += format('flags: ', *BOLD_OUTPUT_FORMAT)
      output += ', '.join(ns_desc.flags) + '\n'

      output += format('exit policy: ', *BOLD_OUTPUT_FORMAT)
      output += exit_policy_label + '\n'

      if server_desc:
        contact = server_desc.contact

        # clears up some highly common obscuring

        for alias in (' at ', ' AT '):
          contact = contact.replace(alias, '@')

        for alias in (' dot ', ' DOT '):
          contact = contact.replace(alias, '.')

        output += format('contact: ', *BOLD_OUTPUT_FORMAT)
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

    if not self.controller.is_alive():
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
        output = format("'%s' isn't a recognized command" % command, *ERROR_FORMAT)

      output += '\n'  # give ourselves an extra line before the next prompt
    else:
      cmd = cmd.upper()  # makes commands uppercase to match the spec

      if cmd == 'GETINFO':
        try:
          response = self.controller.get_info(arg.split())
          output = format('\n'.join(response.values()), *OUTPUT_FORMAT)
        except stem.ControllerError as exc:
          output = format(str(exc), *ERROR_FORMAT)
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
          self.controller.set_options(param_list, is_reset)
        except stem.ControllerError as exc:
          output = format(str(exc), *ERROR_FORMAT)
      elif cmd == 'SETEVENTS':
        try:
          # first discontinue listening to prior events

          self.controller.remove_event_listener(self.register_event)

          # attach listeners for the given group of events

          if arg:
            events = arg.split()
            self.controller.add_event_listener(self.register_event, *events)
            output = format('Listing for %s events\n' % ', '.join(events), *OUTPUT_FORMAT)
          else:
            output = format('Disabled event listening\n', *OUTPUT_FORMAT)
        except stem.ControllerError as exc:
          output = format(str(exc), *ERROR_FORMAT)
      elif cmd.replace('+', '') in ('LOADCONF', 'POSTDESCRIPTOR'):
        # provides a notice that multi-line controller input isn't yet implemented
        output = format(msg('msg.multiline_unimplemented_notice'), *ERROR_FORMAT)
      else:
        try:
          response = self.controller.msg(command)

          if cmd == 'QUIT':
            raise stem.SocketClosed()

          output = format(str(response), *OUTPUT_FORMAT)
        except stem.ControllerError as exc:
          if isinstance(exc, stem.SocketClosed):
            raise exc
          else:
            output = format(str(exc), *ERROR_FORMAT)

    return output
