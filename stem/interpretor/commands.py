"""
Handles making requests and formatting the responses.
"""

import re

import stem

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

MULTILINE_UNIMPLEMENTED_NOTICE = "Multi-line control options like this are not yet implemented."

GENERAL_HELP = """Interpretor commands include:
  /help   - provides information for interpretor and tor commands/config options
  /quit   - shuts down the interpretor

Tor commands include:
  GETINFO - queries information from tor
  GETCONF, SETCONF, RESETCONF - show or edit a configuration option
  SIGNAL - issues control signal to the process (for resetting, stopping, etc)
  SETEVENTS - configures the events tor will notify us of

  USEFEATURE - enables custom behavior for the controller
  SAVECONF - writes tor's current configuration to our torrc
  LOADCONF - loads the given input like it was part of our torrc
  MAPADDRESS - replaces requests for one address with another
  POSTDESCRIPTOR - adds a relay descriptor to our cache
  EXTENDCIRCUIT - create or extend a tor circuit
  SETCIRCUITPURPOSE - configures the purpose associated with a circuit
  CLOSECIRCUIT - closes the given circuit
  ATTACHSTREAM - associates an application's stream with a tor circuit
  REDIRECTSTREAM - sets a stream's destination
  CLOSESTREAM - closes the given stream
  RESOLVE - issues an asynchronous dns or rdns request over tor
  TAKEOWNERSHIP - instructs tor to quit when this control connection is closed
  PROTOCOLINFO - queries version and controller authentication information
  QUIT - disconnect the control connection

For more information use '/help [OPTION]'."""

HELP_HELP = """Provides usage information for the given interpretor, tor command, or tor
configuration option.

Example:
  /help GETINFO     # usage information for tor's GETINFO controller option
"""

HELP_QUIT = """Terminates the interpretor."""

HELP_GETINFO = """Queries the tor process for information. Options are...
"""

HELP_GETCONF = """Provides the current value for a given configuration value. Options include...
"""

HELP_SETCONF = """Sets the given configuration parameters. Values can be quoted or non-quoted
strings, and reverts the option to 0 or NULL if not provided.

Examples:
  * Sets a contact address and resets our family to NULL
    SETCONF MyFamily ContactInfo=foo@bar.com

  * Sets an exit policy that only includes port 80/443
    SETCONF ExitPolicy=\"accept *:80, accept *:443, reject *:*\"\
"""

HELP_RESETCONF = """Reverts the given configuration options to their default values. If a value
is provided then this behaves in the same way as SETCONF.

Examples:
  * Returns both of our accounting parameters to their defaults
    RESETCONF AccountingMax AccountingStart

  * Uses the default exit policy and sets our nickname to be 'Goomba'
    RESETCONF ExitPolicy Nickname=Goomba"""

HELP_SIGNAL = """Issues a signal that tells the tor process to reload its torrc, dump its
stats, halt, etc.
"""

SIGNAL_DESCRIPTIONS = (
  ("RELOAD / HUP", "reload our torrc"),
  ("SHUTDOWN / INT", "gracefully shut down, waiting 30 seconds if we're a relay"),
  ("DUMP / USR1", "logs information about open connections and circuits"),
  ("DEBUG / USR2", "makes us log at the DEBUG runlevel"),
  ("HALT / TERM", "immediately shut down"),
  ("CLEARDNSCACHE", "clears any cached DNS results"),
  ("NEWNYM", "clears the DNS cache and uses new circuits for future connections")
)

HELP_SETEVENTS = """Sets the events that we will receive. This turns off any events that aren't
listed so sending 'SETEVENTS' without any values will turn off all event reporting.

For Tor versions between 0.1.1.9 and 0.2.2.1 adding 'EXTENDED' causes some
events to give us additional information. After version 0.2.2.1 this is
always on.

Events include...

"""

HELP_USEFEATURE = """Customizes the behavior of the control port. Options include...
"""

HELP_SAVECONF = """Writes Tor's current configuration to its torrc."""

HELP_LOADCONF = """Reads the given text like it belonged to our torrc.

Example:
  +LOADCONF
  # sets our exit policy to just accept ports 80 and 443
  ExitPolicy accept *:80
  ExitPolicy accept *:443
  ExitPolicy reject *:*
  ."""

HELP_MAPADDRESS = """Replaces future requests for one address with another.

Example:
  MAPADDRESS 0.0.0.0=torproject.org 1.2.3.4=tor.freehaven.net"""

HELP_POSTDESCRIPTOR = """Simulates getting a new relay descriptor."""

HELP_EXTENDCIRCUIT = """Extends the given circuit or create a new one if the CircuitID is zero. The
PATH is a comma separated list of fingerprints. If it isn't set then this
uses Tor's normal path selection."""

HELP_SETCIRCUITPURPOSE = """Sets the purpose attribute for a circuit."""

HELP_CLOSECIRCUIT = """Closes the given circuit. If "IfUnused" is included then this only closes
the circuit if it isn't currently being used."""

HELP_ATTACHSTREAM = """Attaches a stream with the given built circuit (tor picks one on its own if
CircuitID is zero). If HopNum is given then this hop is used to exit the
circuit, otherwise the last relay is used."""

HELP_REDIRECTSTREAM = """Sets the destination for a given stream. This can only be done after a
stream is created but before it's attached to a circuit."""

HELP_CLOSESTREAM = """Closes the given stream, the reason being an integer matching a reason as
per section 6.3 of the tor-spec."""

HELP_RESOLVE = """Performs IPv4 DNS resolution over tor, doing a reverse lookup instead if
"mode=reverse" is included. This request is processed in the background and
results in a ADDRMAP event with the response."""

HELP_TAKEOWNERSHIP = """Instructs Tor to gracefully shut down when this control connection is closed."""

HELP_PROTOCOLINFO = """Provides bootstrapping information that a controller might need when first
starting, like Tor's version and controller authentication. This can be done
before authenticating to the control port."""

HELP_OPTIONS = {
  "HELP": ("/help [OPTION]", HELP_HELP),
  "QUIT": ("/quit", HELP_QUIT),
  "GETINFO": ("GETINFO OPTION", HELP_GETINFO),
  "GETCONF": ("GETCONF OPTION", HELP_GETCONF),
  "SETCONF": ("SETCONF PARAM[=VALUE]", HELP_SETCONF),
  "RESETCONF": ("RESETCONF PARAM[=VALUE]", HELP_RESETCONF),
  "SIGNAL": ("SIGNAL SIG", HELP_SIGNAL),
  "SETEVENTS": ("SETEVENTS [EXTENDED] [EVENTS]", HELP_SETEVENTS),
  "USEFEATURE": ("USEFEATURE OPTION", HELP_USEFEATURE),
  "SAVECONF": ("SAVECONF", HELP_SAVECONF),
  "LOADCONF": ("LOADCONF...", HELP_LOADCONF),
  "MAPADDRESS": ("MAPADDRESS SOURCE_ADDR=DESTINATION_ADDR", HELP_MAPADDRESS),
  "POSTDESCRIPTOR": ("POSTDESCRIPTOR [purpose=general/controller/bridge] [cache=yes/no]...", HELP_POSTDESCRIPTOR),
  "EXTENDCIRCUIT": ("EXTENDCIRCUIT CircuitID [PATH] [purpose=general/controller]", HELP_EXTENDCIRCUIT),
  "SETCIRCUITPURPOSE": ("SETCIRCUITPURPOSE CircuitID purpose=general/controller", HELP_SETCIRCUITPURPOSE),
  "CLOSECIRCUIT": ("CLOSECIRCUIT CircuitID [IfUnused]", HELP_CLOSECIRCUIT),
  "ATTACHSTREAM": ("ATTACHSTREAM StreamID CircuitID [HOP=HopNum]", HELP_ATTACHSTREAM),
  "REDIRECTSTREAM": ("REDIRECTSTREAM StreamID Address [Port]", HELP_REDIRECTSTREAM),
  "CLOSESTREAM": ("CLOSESTREAM StreamID Reason [Flag]", HELP_CLOSESTREAM),
  "RESOLVE": ("RESOLVE [mode=reverse] address", HELP_RESOLVE),
  "TAKEOWNERSHIP": ("TAKEOWNERSHIP", HELP_TAKEOWNERSHIP),
  "PROTOCOLINFO": ("PROTOCOLINFO [ProtocolVersion]", HELP_PROTOCOLINFO),
}


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
      # provides the GENERAL_HELP with everything bolded except descriptions

      for line in GENERAL_HELP.splitlines():
        cmd_start = line.find(' - ')

        if cmd_start != -1:
          output += format(line[:cmd_start], *BOLD_OUTPUT_FORMAT)
          output += format(line[cmd_start:] + '\n', *OUTPUT_FORMAT)
        else:
          output += format(line + '\n', *BOLD_OUTPUT_FORMAT)
    elif arg in HELP_OPTIONS:
      # Provides information for the tor or interpretor argument. This bolds
      # the usage information and indents the description after it.

      usage, description = HELP_OPTIONS[arg]

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
        output += format('\n' + MULTILINE_UNIMPLEMENTED_NOTICE + '\n', *ERROR_FORMAT)
    else:
      output += format("No help information available for '%s'..." % arg, *ERROR_FORMAT)

    return output

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
        pass  # TODO: implement
      elif cmd.replace('+', '') in ('LOADCONF', 'POSTDESCRIPTOR'):
        # provides a notice that multi-line controller input isn't yet implemented
        output = format(MULTILINE_UNIMPLEMENTED_NOTICE, *ERROR_FORMAT)
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
