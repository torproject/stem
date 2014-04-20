"""
Tab completion for our interpretor prompt.
"""

from stem.interpretor import uses_settings

try:
  # added in python 3.2
  from functools import lru_cache
except ImportError:
  from stem.util.lru_cache import lru_cache


@uses_settings
def _get_commands(config, controller):
  """
  Provides commands recognized by tor.
  """

  commands = config.get('autocomplete', [])

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

  # adds help options for the previous commands

  base_cmd = set([cmd.split(' ')[0].replace('+', '').replace('/', '') for cmd in commands])

  for cmd in base_cmd:
    commands.append('/help ' + cmd)

  return commands


class Autocompleter(object):
  def __init__(self, controller):
    self._commands = _get_commands(controller)

  @lru_cache()
  def matches(self, text):
    """
    Provides autocompletion matches for the given text.

    :param str text: text to check for autocompletion matches with

    :returns: **list** with possible matches
    """

    lowercase_text = text.lower()
    return [cmd for cmd in self._commands if cmd.lower().startswith(lowercase_text)]

  def complete(self, text, state):
    """
    Provides case insensetive autocompletion options, acting as a functor for
    the readlines set_completer function.

    :param str text: text to check for autocompletion matches with
    :param int state: index of result to be provided, readline fetches matches
      until this function provides None

    :returns: **str** with the autocompletion match, **None** if eithe none
      exists or state is higher than our number of matches
    """

    try:
      return self.matches(text)[state]
    except IndexError:
      return None
