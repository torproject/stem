# Copyright 2014, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interactive interpretor for interacting with Tor directly. This adds usability
features such as tab completion, history, and IRC-style functions (like /help).
"""

__all__ = ['arguments', 'autocomplete', 'commands', 'help', 'msg']

import code
import os
import sys

import stem
import stem.connection
import stem.process
import stem.util.conf
import stem.util.system

from stem.util.term import RESET, Attr, Color, format

# Our color prompt triggers a bug between raw_input() and readline history,
# where scrolling through history widens our prompt. Widening our prompt via
# invisible characters (like resets) seems to sidestep this bug for short
# inputs. Contrary to the ticket, this still manifests with python 2.7.1...
#
#   http://bugs.python.org/issue12972

PROMPT = format('>>> ', Color.GREEN, Attr.BOLD) + RESET * 10

STANDARD_OUTPUT = (Color.BLUE, )
BOLD_OUTPUT = (Color.BLUE, Attr.BOLD)
ERROR_OUTPUT = (Attr.BOLD, Color.RED)

settings_path = os.path.join(os.path.dirname(__file__), 'settings.cfg')
uses_settings = stem.util.conf.uses_settings('stem_interpretor', settings_path)


@uses_settings
def msg(message, config, **attr):
  return config.get(message).format(**attr)


def main():
  import readline

  import stem.interpretor.arguments
  import stem.interpretor.autocomplete
  import stem.interpretor.commands

  try:
    args = stem.interpretor.arguments.parse(sys.argv[1:])
  except ValueError as exc:
    print exc
    sys.exit(1)

  if args.print_help:
    print stem.interpretor.arguments.get_help()
    sys.exit()

  # If the user isn't connecting to something in particular then offer to start
  # tor if it isn't running.

  if not (args.user_provided_port or args.user_provided_socket):
    is_tor_running = stem.util.system.is_running('tor') or stem.util.system.is_running('tor.real')

    if not is_tor_running:
      if not stem.util.system.is_available('tor'):
        print msg('msg.tor_unavailable')
        sys.exit(1)
      else:
        user_input = raw_input(msg('msg.start_tor_prompt'))
        print  # extra newline

        if user_input.lower() not in ('y', 'yes'):
          sys.exit()

        stem.process.launch_tor_with_config(
          config = {
            'SocksPort': '0',
            'ControlPort': str(args.control_port),
            'CookieAuthentication': '1',
            'ExitPolicy': 'reject *:*',
          },
          completion_percent = 5,
          take_ownership = True,
        )

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
    if args.python_prompt:
      console = code.InteractiveConsole({
        'controller': controller,
        'stem': stem,
        'stem.control': stem.control,
      })
      console.interact(msg('msg.python_banner', version = controller.get_info('version')))
    else:
      autocompleter = stem.interpretor.autocomplete.Autocompleter(controller)
      readline.parse_and_bind('tab: complete')
      readline.set_completer(autocompleter.complete)
      readline.set_completer_delims('\n')

      interpretor = stem.interpretor.commands.ControlInterpretor(controller)

      while True:
        try:
          user_input = raw_input(PROMPT)
          print interpretor.run_command(user_input)
        except (KeyboardInterrupt, EOFError, stem.SocketClosed) as exc:
          print  # move cursor to the following line
          break
