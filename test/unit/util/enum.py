"""
Unit tests for the stem.util.enum class and functions.
"""

import unittest

import stem.util.enum


class TestEnum(unittest.TestCase):
  def test_enum_examples(self):
    """
    Checks that the pydoc examples are accurate.
    """

    insects = stem.util.enum.Enum('ANT', 'WASP', 'LADYBUG', 'FIREFLY')
    self.assertEqual('Ant', insects.ANT)
    self.assertEqual(('Ant', 'Wasp', 'Ladybug', 'Firefly'), tuple(insects))

    pets = stem.util.enum.Enum(('DOG', 'Skippy'), 'CAT', ('FISH', 'Nemo'))
    self.assertEqual('Skippy', pets.DOG)
    self.assertEqual('Cat', pets.CAT)

  def test_uppercase_enum_example(self):
    """
    Checks that the pydoc example for the UppercaseEnum constructor function is
    accurate.
    """

    runlevels = stem.util.enum.UppercaseEnum('DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR')
    self.assertEqual('DEBUG', runlevels.DEBUG)

  def test_enum_methods(self):
    """
    Exercises enumeration methods.
    """

    insects = stem.util.enum.Enum('ANT', 'WASP', 'LADYBUG', 'FIREFLY')

    # next method
    self.assertEqual(insects.WASP, insects.next(insects.ANT))
    self.assertEqual(insects.ANT, insects.next(insects.FIREFLY))

    # previous method
    self.assertEqual(insects.FIREFLY, insects.previous(insects.ANT))
    self.assertEqual(insects.LADYBUG, insects.previous(insects.FIREFLY))

    # keys method
    self.assertEqual(['ANT', 'WASP', 'LADYBUG', 'FIREFLY'], list(insects.keys()))
