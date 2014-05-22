"""
Unit tests for the stem's interpreter prompt.
"""

__all__ = [
  'arguments',
  'autocomplete',
  'commands',
  'help',
]

try:
  # added in python 3.3
  from unittest.mock import Mock
except ImportError:
  from mock import Mock

GETINFO_NAMES = """
info/names -- List of GETINFO options, types, and documentation.
ip-to-country/* -- Perform a GEOIP lookup
md/id/* -- Microdescriptors by ID
""".strip()

GETCONF_NAMES = """
ExitNodes RouterList
ExitPolicy LineList
ExitPolicyRejectPrivate Boolean
""".strip()


CONTROLLER = Mock()

CONTROLLER.get_info.side_effect = lambda arg, _: {
  'info/names': GETINFO_NAMES,
  'config/names': GETCONF_NAMES,
  'events/names': 'BW DEBUG INFO NOTICE',
  'features/names': 'VERBOSE_NAMES EXTENDED_EVENTS',
  'signal/names': 'RELOAD HUP SHUTDOWN',
}[arg]
