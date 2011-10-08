#!/usr/bin/env python

"""
Runs unit and integration tests.
"""

import unittest
import test.unit.version

if __name__ == '__main__':
  suite = unittest.TestLoader().loadTestsFromTestCase(test.unit.version.TestVerionFunctions)
  unittest.TextTestRunner(verbosity=2).run(suite)

