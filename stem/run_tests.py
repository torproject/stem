#!/usr/bin/env python

"""
Runs unit and integration tests.
"""

import unittest
import test.types

if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromTestCase(test.types.TestVerionFunctions)
  unittest.TextTestRunner(verbosity=2).run(suite)

