"""
Handles making requests and formatting the responses.
"""

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
