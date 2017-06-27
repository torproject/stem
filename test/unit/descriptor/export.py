"""
Unit tests for stem.descriptor.export.
"""

import unittest

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

import stem.prereq

from stem.descriptor.server_descriptor import RelayDescriptor, BridgeDescriptor
from stem.descriptor.export import export_csv, export_csv_file


class TestExport(unittest.TestCase):
  def test_minimal_descriptor(self):
    """
    Exports a single minimal tor server descriptor.
    """

    if stem.prereq._is_python_26():
      self.skipTest('(header added in python 2.7)')
      return

    desc = RelayDescriptor.create({
      'router': 'caerSidi 71.35.133.197 9001 0 0',
      'published': '2012-03-01 17:15:27',
    })

    desc_csv = export_csv(desc, included_fields = ('nickname', 'address', 'published'), header = False)
    expected = 'caerSidi,71.35.133.197,2012-03-01 17:15:27\n'
    self.assertEqual(expected, desc_csv)

    desc_csv = export_csv(desc, included_fields = ('nickname', 'address', 'published'), header = True)
    expected = 'nickname,address,published\n' + expected
    self.assertEqual(expected, desc_csv)

  def test_multiple_descriptors(self):
    """
    Exports multiple descriptors, making sure that we get them back in the same
    order.
    """

    nicknames = ('relay1', 'relay3', 'relay2', 'caerSidi', 'zeus')
    descriptors = []

    for nickname in nicknames:
      router_line = '%s 71.35.133.197 9001 0 0' % nickname
      descriptors.append(RelayDescriptor.create({'router': router_line}))

    expected = '\n'.join(nicknames) + '\n'
    self.assertEqual(expected, export_csv(descriptors, included_fields = ('nickname',), header = False))

  def test_file_output(self):
    """
    Basic test for the export_csv_file() function, checking that it provides
    the same output as export_csv().
    """

    desc = RelayDescriptor.create()
    desc_csv = export_csv(desc)

    csv_buffer = StringIO()
    export_csv_file(csv_buffer, desc)

    self.assertEqual(desc_csv, csv_buffer.getvalue())

  def test_excludes_private_attr(self):
    """
    Checks that the default attributes for our csv output doesn't include private fields.
    """

    if stem.prereq._is_python_26():
      self.skipTest('(header added in python 2.7)')
      return

    desc = RelayDescriptor.create()
    desc_csv = export_csv(desc)

    self.assertTrue(',signature' in desc_csv)
    self.assertFalse(',_digest' in desc_csv)
    self.assertFalse(',_annotation_lines' in desc_csv)

  def test_empty_input(self):
    """
    Exercises when we don't provide any descriptors.
    """
    self.assertEqual('', export_csv([]))

  def test_invalid_attributes(self):
    """
    Attempts to make a csv with attributes that don't exist.
    """

    desc = RelayDescriptor.create()
    self.assertRaises(ValueError, export_csv, desc, ('nickname', 'blarg!'))

  def test_multiple_descriptor_types(self):
    """
    Attempts to make a csv with multiple descriptor types.
    """

    self.assertRaises(ValueError, export_csv, (RelayDescriptor.create(), BridgeDescriptor.create()))
