"""
Unit tests for stem.descriptor.networkstatus.
"""

import unittest

from stem.descriptor import networkstatus

class TestNetworkStatus(unittest.TestCase):
  def test_fingerprint_decoding(self):
    """
    Tests for the _decode_fingerprint() helper.
    """
    
    # consensus identity field and fingerprint for caerSidi and Amunet1-5
    test_values = {
      'p1aag7VwarGxqctS7/fS0y5FU+s': 'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB',
      'IbhGa8T+8tyy/MhxCk/qI+EI2LU': '21B8466BC4FEF2DCB2FCC8710A4FEA23E108D8B5',
      '20wYcbFGwFfMktmuffYj6Z1RM9k': 'DB4C1871B146C057CC92D9AE7DF623E99D5133D9',
      'nTv9AG1cZeFW2hXiSIEAF6JLRJ4': '9D3BFD006D5C65E156DA15E248810017A24B449E',
      '/UKsQiOSGPi/6es0/ha1prNTeDI': 'FD42AC42239218F8BFE9EB34FE16B5A6B3537832',
      '/nHdqoKZ6bKZixxAPzYt9Qen+Is': 'FE71DDAA8299E9B2998B1C403F362DF507A7F88B',
    }
    
    for arg, expected in test_values.items():
      self.assertEqual(expected, networkstatus._decode_fingerprint(arg))

