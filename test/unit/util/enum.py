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
    self.assertEquals('Ant', insects.ANT)
    self.assertEquals(('Ant', 'Wasp', 'Ladybug', 'Firefly'), tuple(insects))

    pets = stem.util.enum.Enum(('DOG', 'Skippy'), 'CAT', ('FISH', 'Nemo'))
    self.assertEquals('Skippy', pets.DOG)
    self.assertEquals('Cat', pets.CAT)

  def test_uppercase_enum_example(self):
    """
    Checks that the pydoc example for the UppercaseEnum constructor function is
    accurate.
    """

    runlevels = stem.util.enum.UppercaseEnum('DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR')
    self.assertEquals('DEBUG', runlevels.DEBUG)

  def test_enum_methods(self):
    """
    Exercises enumeration methods.
    """

    insects = stem.util.enum.Enum('ANT', 'WASP', 'LADYBUG', 'FIREFLY')

    # next method
    self.assertEquals(insects.WASP, insects.next(insects.ANT))
    self.assertEquals(insects.ANT, insects.next(insects.FIREFLY))

    # previous method
    self.assertEquals(insects.FIREFLY, insects.previous(insects.ANT))
    self.assertEquals(insects.LADYBUG, insects.previous(insects.FIREFLY))

    # keys method
    self.assertEquals(['ANT', 'WASP', 'LADYBUG', 'FIREFLY'], insects.keys())
