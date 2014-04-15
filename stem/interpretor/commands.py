"""
Handles making requests and formatting the responses.
"""

import os
import re

import stem
import stem.util.conf
import stem.util.log

from stem.util.term import Attr, Color, format

OUTPUT_FORMAT = (Color.BLUE, )
BOLD_OUTPUT_FORMAT = (Color.BLUE, Attr.BOLD)
ERROR_FORMAT = (Attr.BOLD, Color.RED)

TOR_CONTROLLER_COMMANDS = [
  'SAVECONF',
  'MAPADDRESS',
  'EXTENDCIRCUIT',
  'SETCIRCUITPURPOSE',
  'SETROUTERPURPOSE',
  'ATTACHSTREAM',
  #'+POSTDESCRIPTOR',  # TODO: needs multi-line support
  'REDIRECTSTREAM',
  'CLOSESTREAM',
  'CLOSECIRCUIT',
  'QUIT',
  'RESOLVE',
  'PROTOCOLINFO',
  #'+LOADCONF',  # TODO: needs multi-line support
  'TAKEOWNERSHIP',
  'AUTHCHALLENGE',
  'DROPGUARDS',
]

SIGNAL_DESCRIPTIONS = (
  ("RELOAD / HUP", "reload our torrc"),
  ("SHUTDOWN / INT", "gracefully shut down, waiting 30 seconds if we're a relay"),
  ("DUMP / USR1", "logs information about open connections and circuits"),
  ("DEBUG / USR2", "makes us log at the DEBUG runlevel"),
  ("HALT / TERM", "immediately shut down"),
  ("CLEARDNSCACHE", "clears any cached DNS results"),
  ("NEWNYM", "clears the DNS cache and uses new circuits for future connections")
)

HELP_OPTIONS = {
  'HELP': ("/help [OPTION]", 'help.help'),
  'EVENTS': ("/events [types]", 'help.events'),
  'QUIT': ("/quit", 'help.quit'),
  'GETINFO': ("GETINFO OPTION", 'help.getinfo'),
  'GETCONF': ("GETCONF OPTION", 'help.getconf'),
  'SETCONF': ("SETCONF PARAM[=VALUE]", 'help.setconf'),
  'RESETCONF': ("RESETCONF PARAM[=VALUE]", 'help.resetconf'),
  'SIGNAL': ("SIGNAL SIG", 'help.signal'),
  'SETEVENTS': ("SETEVENTS [EXTENDED] [EVENTS]", 'help.setevents'),
  'USEFEATURE': ("USEFEATURE OPTION", 'help.usefeature'),
  'SAVECONF': ("SAVECONF", 'help.saveconf'),
  'LOADCONF': ("LOADCONF...", 'help.loadconf'),
  'MAPADDRESS': ("MAPADDRESS SOURCE_ADDR=DESTINATION_ADDR", 'help.mapaddress'),
  'POSTDESCRIPTOR': ("POSTDESCRIPTOR [purpose=general/controller/bridge] [cache=yes/no]...", 'help.postdescriptor'),
  'EXTENDCIRCUIT': ("EXTENDCIRCUIT CircuitID [PATH] [purpose=general/controller]", 'help.extendcircuit'),
  'SETCIRCUITPURPOSE': ("SETCIRCUITPURPOSE CircuitID purpose=general/controller", 'help.setcircuitpurpose'),
  'CLOSECIRCUIT': ("CLOSECIRCUIT CircuitID [IfUnused]", 'help.closecircuit'),
  'ATTACHSTREAM': ("ATTACHSTREAM StreamID CircuitID [HOP=HopNum]", 'help.attachstream'),
  'REDIRECTSTREAM': ("REDIRECTSTREAM StreamID Address [Port]", 'help.redirectstream'),
  'CLOSESTREAM': ("CLOSESTREAM StreamID Reason [Flag]", 'help.closestream'),
  'RESOLVE': ("RESOLVE [mode=reverse] address", 'help.resolve'),
  'TAKEOWNERSHIP': ("TAKEOWNERSHIP", 'help.takeownership'),
  'PROTOCOLINFO': ("PROTOCOLINFO [ProtocolVersion]", 'help.protocolinfo'),
}


def uses_settings(func):
  """
  Loads our interpretor's internal settings. This should be treated as a fatal
  failure if unsuccessful.

  :raises: **IOError** if we're unable to read or parse our internal
    configurations
  """

  config = stem.util.conf.get_config('stem_interpretor')

  if not config.get('settings_loaded', False):
    settings_path = os.path.join(os.path.dirname(__file__), 'settings.cfg')
    config.load(settings_path)
    config.set('settings_loaded', 'true')

  return func


def _get_commands(controller):
  """
  Provides commands recognized by tor.
  """

  commands = list(TOR_CONTROLLER_COMMANDS)

  # GETINFO commands

  getinfo_options = controller.get_info('info/names', None)

  if getinfo_options:
    # Lines are of the form '[option] -- [description]'. This strips '*' from
    # options that accept values.

    options = [line.split(' ', 1)[0].rstrip('*') for line in getinfo_options.splitlines()]

    commands += ['GETINFO %s' % opt for opt in options]
  else:
    commands.append('GETINFO ')

  # GETCONF, SETCONF, and RESETCONF commands

  config_options = controller.get_info('config/names', None)

  if config_options:
    # individual options are '[option] [type]' pairs

    entries = [opt.split(' ', 1)[0] for opt in config_options.splitlines()]

    commands += ['GETCONF %s' % opt for opt in entries]
    commands += ['SETCONF %s ' % opt for opt in entries]
    commands += ['RESETCONF %s' % opt for opt in entries]
  else:
    commands += ['GETCONF ', 'SETCONF ', 'RESETCONF ']

  # SETEVENT commands

  events = controller.get_info('events/names', None)

  if events:
    commands += ['SETEVENTS %s' % event for event in events.split(' ')]
  else:
    commands.append('SETEVENTS ')

  # USEFEATURE commands

  features = controller.get_info('features/names', None)

  if features:
    commands += ['USEFEATURE %s' % feature for feature in features.split(' ')]
  else:
    commands.append('USEFEATURE ')

  # SIGNAL commands

  signals = controller.get_info('signal/names', None)

  if signals:
    commands += ['SIGNAL %s' % signal for signal in signals.split(' ')]
  else:
    commands.append('SIGNAL ')

  # adds interpretor commands

  for cmd in HELP_OPTIONS:
    if HELP_OPTIONS[cmd][0].startswith('/'):
      commands.append('/' + cmd.lower())

  # adds help options for the previous commands

  base_cmd = set([cmd.split(' ')[0].replace('+', '').replace('/', '') for cmd in commands])

  for cmd in base_cmd:
    commands.append('/help ' + cmd)

  return commands


class Autocomplete(object):
  def __init__(self, controller):
    self._commands = _get_commands(controller)

  def complete(self, text, state):
    """
    Provides case insensetive autocompletion options, acting as a functor for
    the readlines set_completer function.
    """

    lowercase_text = text.lower()
    prefix_matches = [cmd for cmd in self._commands if cmd.lower().startswith(lowercase_text)]

    if state < len(prefix_matches):
      return prefix_matches[state]
    else:
      return None


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

  def do_help(self, arg):
    """
    Performs the '/help' operation, giving usage information for the given
    argument or a general summary if there wasn't one.
    """

    arg = arg.upper()

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
    elif arg in HELP_OPTIONS:
      # Provides information for the tor or interpretor argument. This bolds
      # the usage information and indents the description after it.

      usage, attr = HELP_OPTIONS[arg]
      description = msg(attr)

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

        for signal, description in SIGNAL_DESCRIPTIONS:
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
      if cmd == "/quit":
        raise stem.SocketClosed()
      elif cmd == "/events":
        output = self.do_events(arg)
      elif cmd == "/help":
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


@uses_settings
def msg(message, **attr):
  """
  Provides the given message.

  :param str message: message handle
  :param dict attr: attributes to format the message with

  :returns: **str** that was requested
  """

  config = stem.util.conf.get_config('stem_interpretor')

  try:
    return config.get(message).format(**attr)
  except:
    stem.util.log.notice('BUG: We attempted to use an undefined string resource (%s)' % message)
    return ''
