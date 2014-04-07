# Copyright 2014, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interactive interpretor for interacting with Tor directly. This adds usability
features such as tab completion, history, and IRC-style functions (like /help).
"""

__all__ = ['arguments']

import sys

import stem.connection
import stem.interpretor.arguments
import stem.interpretor.commands
import stem.prereq

from stem.util.term import Attr, Color, format

# We can only present a color prompt with python 2.7 or later...
#
#   http://bugs.python.org/issue12972

if stem.prereq.is_python_27():
  PROMPT = format(">>> ", Color.GREEN, Attr.BOLD)
else:
  PROMPT = ">>> "


def main():
  import readline

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
    tab_completer = stem.interpretor.commands.Autocomplete(controller)
    readline.parse_and_bind("tab: complete")
    readline.set_completer(tab_completer.complete)
    readline.set_completer_delims('\n')

    while True:
      try:
        user_input = raw_input(PROMPT)
        print controller.msg(user_input)
      except KeyboardInterrupt as exc:
        print  # move cursor to the following line
        break
