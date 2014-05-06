"""
Handles making requests and formatting the responses.
"""

import re

import stem
import stem.interpretor.help
import stem.util.connection
import stem.util.tor_tools

from stem.interpretor import STANDARD_OUTPUT, BOLD_OUTPUT, ERROR_OUTPUT, msg
from stem.util.term import format


def _get_fingerprint(arg, controller):
  """
  Resolves user input into a relay fingerprint. This accepts...

    * Fingerprints
    * Nicknames
    * IPv4 addresses, either with or without an ORPort
    * Empty input, which is resolved to ourselves if we're a relay

  :param str arg: input to be resolved to a relay fingerprint
  :param stem.control.Controller controller: tor control connection

  :returns: **str** for the relay fingerprint

  :raises: **ValueError** if we're unable to resolve the input to a relay
  """

  if not arg:
    try:
      return controller.get_info('fingerprint')
    except:
      raise ValueError("We aren't a relay, no information to provide")
  elif stem.util.tor_tools.is_valid_fingerprint(arg):
    return arg
  elif stem.util.tor_tools.is_valid_nickname(arg):
    try:
      return controller.get_network_status(arg).fingerprint
    except:
      raise ValueError("Unable to find a relay with the nickname of '%s'" % arg)
  elif ':' in arg or stem.util.connection.is_valid_ipv4_address(arg):
    if ':' in arg:
      address, port = arg.split(':', 1)

      if not stem.util.connection.is_valid_ipv4_address(address):
        raise ValueError("'%s' isn't a valid IPv4 address" % address)
      elif port and not stem.util.connection.is_valid_port(port):
        raise ValueError("'%s' isn't a valid port" % port)

      port = int(port)
    else:
      address, port = arg, None

    matches = {}

    for desc in controller.get_network_statuses():
      if desc.address == address:
        if not port or desc.or_port == port:
          matches[desc.or_port] = desc.fingerprint

    if len(matches) == 0:
      raise ValueError('No relays found at %s' % arg)
    elif len(matches) == 1:
      return matches.values()[0]
    else:
      response = "There's multiple relays at %s, include a port to specify which.\n\n" % arg

      for i, or_port in enumerate(matches):
        response += "  %i. %s:%s, fingerprint: %s\n" % (i + 1, address, or_port, matches[or_port])

      raise ValueError(response)
  else:
    raise ValueError("'%s' isn't a fingerprint, nickname, or IP address" % arg)


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

    return stem.interpretor.help.response(self._controller, arg)

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

    try:
      fingerprint = _get_fingerprint(arg, self._controller)
    except ValueError as exc:
      return format(str(exc), *ERROR_OUTPUT)

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

    lines = [
      '%s (%s)' % (ns_desc.nickname, fingerprint),
      format('address: ', *BOLD_OUTPUT) + '%s:%s%s' % (ns_desc.address, ns_desc.or_port, locale_label),
      format('published: ', *BOLD_OUTPUT) + ns_desc.published.strftime('%H:%M:%S %d/%m/%Y'),
    ]

    if server_desc:
      lines.append(format('os: ', *BOLD_OUTPUT) + server_desc.platform.decode('utf-8', 'replace'))
      lines.append(format('version: ', *BOLD_OUTPUT) + str(server_desc.tor_version))

    lines.append(format('flags: ', *BOLD_OUTPUT) + ', '.join(ns_desc.flags))
    lines.append(format('exit policy: ', *BOLD_OUTPUT) + exit_policy_label)

    if server_desc:
      contact = server_desc.contact

      # clears up some highly common obscuring

      for alias in (' at ', ' AT '):
        contact = contact.replace(alias, '@')

      for alias in (' dot ', ' DOT '):
        contact = contact.replace(alias, '.')

      lines.append(format('contact: ', *BOLD_OUTPUT) + contact)

    return '\n'.join(lines)

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
      elif cmd == 'GETCONF':
        try:
          response = self._controller.get_conf_map(arg.split())

          for arg in response:
            output += format(arg, *BOLD_OUTPUT) + format(' => ' + ', '.join(response[arg]), *STANDARD_OUTPUT) + '\n'
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
