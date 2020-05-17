# Copyright 2014-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Tab completion for our interpreter prompt.
"""

import functools

import stem.control
import stem.util.conf

from stem.interpreter import uses_settings
from typing import List, Optional


@uses_settings
def _get_commands(controller: stem.control.Controller, config: stem.util.conf.Config) -> List[str]:
  """
  Provides commands recognized by tor.
  """

  commands = config.get('autocomplete', [])

  if controller is None:
    return commands

  # GETINFO commands. Lines are of the form '[option] -- [description]'. This
  # strips '*' from options that accept values.

  results = controller.get_info('info/names', None)

  if results:
    for line in results.splitlines():
      option = line.split(' ', 1)[0].rstrip('*')
      commands.append('GETINFO %s' % option)
  else:
    commands.append('GETINFO ')

  # GETCONF, SETCONF, and RESETCONF commands. Lines are of the form
  # '[option] [type]'.

  results = controller.get_info('config/names', None)

  if results:
    for line in results.splitlines():
      option = line.split(' ', 1)[0]

      commands.append('GETCONF %s' % option)
      commands.append('SETCONF %s' % option)
      commands.append('RESETCONF %s' % option)
  else:
    commands += ['GETCONF ', 'SETCONF ', 'RESETCONF ']

  # SETEVENT, USEFEATURE, and SIGNAL commands. For each of these the GETINFO
  # results are simply a space separated lists of the values they can have.

  options = (
    ('SETEVENTS ', 'events/names'),
    ('USEFEATURE ', 'features/names'),
    ('SIGNAL ', 'signal/names'),
  )

  for prefix, getinfo_cmd in options:
    results = controller.get_info(getinfo_cmd, None)

    if results:
      commands += [prefix + value for value in results.split()]
    else:
      commands.append(prefix)

  # Adds /help commands.

  usage_info = config.get('help.usage', {})

  for cmd in usage_info.keys():
    commands.append('/help ' + cmd)

  return commands


class Autocompleter(object):
  def __init__(self, controller: stem.control.Controller) -> None:
    self._commands = _get_commands(controller)

  @functools.lru_cache()
  def matches(self, text: str) -> List[str]:
    """
    Provides autocompletion matches for the given text.

    :param text: text to check for autocompletion matches with

    :returns: **list** with possible matches
    """

    lowercase_text = text.lower()
    return [cmd for cmd in self._commands if cmd.lower().startswith(lowercase_text)]

  def complete(self, text: str, state: int) -> Optional[str]:
    """
    Provides case insensetive autocompletion options, acting as a functor for
    the readlines set_completer function.

    :param text: text to check for autocompletion matches with
    :param state: index of result to be provided, readline fetches matches
      until this function provides None

    :returns: **str** with the autocompletion match, **None** if eithe none
      exists or state is higher than our number of matches
    """

    try:
      return self.matches(text)[state]
    except IndexError:
      return None
