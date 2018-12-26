"""
Unit tests for the base stem.descriptor module.
"""

import unittest

from stem.descriptor import Descriptor
from stem.descriptor.server_descriptor import RelayDescriptor


class TestDescriptor(unittest.TestCase):
  def test_from_str(self):
    """
    Basic exercise for Descriptor.from_str().
    """

    desc_text = RelayDescriptor.content({'router': 'caerSidi 71.35.133.197 9001 0 0'})
    desc = Descriptor.from_str(desc_text, descriptor_type = 'server-descriptor 1.0')
    self.assertEqual('caerSidi', desc.nickname)

  def test_from_str_type_handling(self):
    """
    Check our various methods of conveying the descriptor type. There's three:
    @type annotations, a descriptor_type argument, and using the from_str() of
    a particular subclass.
    """

    desc_text = RelayDescriptor.content({'router': 'caerSidi 71.35.133.197 9001 0 0'})

    desc = Descriptor.from_str(desc_text, descriptor_type = 'server-descriptor 1.0')
    self.assertEqual('caerSidi', desc.nickname)

    desc = Descriptor.from_str(b'@type server-descriptor 1.0\n' + desc_text)
    self.assertEqual('caerSidi', desc.nickname)

    desc = RelayDescriptor.from_str(desc_text)
    self.assertEqual('caerSidi', desc.nickname)

    self.assertRaisesWith(TypeError, "Unable to determine the descriptor's type. filename: '<undefined>', first line: 'router caerSidi 71.35.133.197 9001 0 0'", Descriptor.from_str, desc_text)

  def test_from_str_multiple(self):
    desc_text = b'\n'.join((
      b'@type server-descriptor 1.0',
      RelayDescriptor.content({'router': 'relay1 71.35.133.197 9001 0 0'}),
      RelayDescriptor.content({'router': 'relay2 71.35.133.197 9001 0 0'}),
    ))

    self.assertEqual(2, len(RelayDescriptor.from_str(desc_text, multiple = True)))
    self.assertEqual(0, len(RelayDescriptor.from_str('', multiple = True)))

    self.assertRaisesWith(ValueError, "Descriptor.from_str() expected a single descriptor, but had 2 instead. Please include 'multiple = True' if you want a list of results instead.", RelayDescriptor.from_str, desc_text)
