"""
Unit tests for the stem.control module. The module's primarily exercised via
integ tests, but a few bits lend themselves to unit testing.
"""

import unittest

from stem import ProtocolError
from stem.control import _parse_circ_path

class TestControl(unittest.TestCase):
  def test_parse_circ_path(self):
    """
    Exercises the _parse_circ_path() helper function.
    """
    
    # empty input
    
    self.assertEqual([], _parse_circ_path(None))
    self.assertEqual([], _parse_circ_path(''))
    
    # check the pydoc examples
    
    pydoc_examples = {
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz':
        [('999A226EBED397F331B612FE1E4CFAE5C1F201BA', 'piyaz')],
      '$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone,PrivacyRepublic14':
        [('E57A476CD4DFBD99B4EE52A100A58610AD6E80B9', None),
         (None, 'hamburgerphone'),
         (None, 'PrivacyRepublic14'),
        ],
    }
    
    for test_input, expected in pydoc_examples.items():
      self.assertEqual(expected, _parse_circ_path(test_input))
    
    # exercise with some invalid inputs
    
    malformed_inputs = [
      '=piyaz', # no fingerprint
      '999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz', # fingerprint missing prefix
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BAA=piyaz', # fingerprint too long
      '$999A226EBED397F331B612FE1E4CFAE5C1F201B=piyaz', # fingerprint too short
      '$999A226EBED397F331B612FE1E4CFAE5C1F201Bz=piyaz', # invalid character in fingerprint
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BA=', # no nickname
    ]
    
    for test_input in malformed_inputs:
      self.assertRaises(ProtocolError, _parse_circ_path, test_input)

