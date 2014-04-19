# Copyright 2014, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interactive interpretor for interacting with Tor directly. This adds usability
features such as tab completion, history, and IRC-style functions (like /help).
"""

__all__ = ['arguments', 'commands', 'msg']

import os
import sys

import stem
import stem.connection
import stem.util.conf

from stem.util.term import RESET, Attr, Color, format

# Our color prompt triggers a bug between raw_input() and readline history,
# where scrolling through history widens our prompt. Widening our prompt via
# invisible characters (like resets) seems to sidestep this bug for short
# inputs. Contrary to the ticket, this still manifests with python 2.7.1...
#
#   http://bugs.python.org/issue12972

PROMPT = format(">>> ", Color.GREEN, Attr.BOLD) + RESET * 10

settings_path = os.path.join(os.path.dirname(__file__), 'settings.cfg')
uses_settings = stem.util.conf.uses_settings('stem_interpretor', settings_path)


@uses_settings
def msg(config, message, **attr):
  return config.get(message).format(**attr)


def main():
  import readline

  import stem.interpretor.arguments
  import stem.interpretor.commands

  try:
    args = stem.interpretor.arguments.parse(sys.argv[1:])
  except ValueError as exc:
    print exc
    sys.exit(1)

  if args.print_help:
    print stem.interpretor.arguments.get_help()
    sys.exit()

  control_port = None if args.user_provided_socket else (args.control_address, args.control_port)
  control_socket = None if args.user_provided_port else args.control_socket

  controller = stem.connection.connect(
    control_port = control_port,
    control_socket = control_socket,
    password_prompt = True,
  )

  if controller is None:
    sys.exit(1)

  with controller:
    autocomplete = stem.interpretor.commands.Autocomplete(controller)
    readline.parse_and_bind('tab: complete')
    readline.set_completer(autocomplete.complete)
    readline.set_completer_delims('\n')

    interpretor = stem.interpretor.commands.ControlInterpretor(controller)

    while True:
      try:
        user_input = raw_input(PROMPT)
        print interpretor.run_command(user_input)
      except (KeyboardInterrupt, EOFError, stem.SocketClosed) as exc:
        print  # move cursor to the following line
        break
