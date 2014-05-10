"""
Unit tests for the BridgeNetworkStatusDocument of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import BridgeNetworkStatusDocument

DOCUMENT = b"""\
published 2012-06-01 04:07:04
r Unnamed ABSiBVJ42z6w5Z6nAXQUFq8YVVg FI74aFuNJZZQrgln0f+OaocMd0M 2012-05-31 15:57:00 10.97.236.247 443 0
s Valid
w Bandwidth=55
p reject 1-65535
r TolFuin AFn9TveYjdtZEsgh7QsWp3qC5kU 1Sw8RPx2Tq/w+VHL+pZipiJUG5k 2012-05-31 18:12:39 10.99.47.37 80 0
s Fast Guard Running Stable Valid
w Bandwidth=32
p reject 1-65535
"""


class TestBridgeNetworkStatusDocument(unittest.TestCase):
  def test_empty_document(self):
    """
    Parse a document without any router status entries.
    """

    document = BridgeNetworkStatusDocument(b'published 2012-06-01 04:07:04')
    self.assertEqual(datetime.datetime(2012, 6, 1, 4, 7, 4), document.published)
    self.assertEqual({}, document.routers)
    self.assertEqual([], document.get_unrecognized_lines())

  def test_document(self):
    """
    Parse a document with router status entries.
    """

    document = BridgeNetworkStatusDocument(DOCUMENT)
    self.assertEqual(datetime.datetime(2012, 6, 1, 4, 7, 4), document.published)

    self.assertEqual(2, len(document.routers))
    self.assertEqual(set(['Unnamed', 'TolFuin']), set([desc.nickname for desc in document.routers.values()]))
    self.assertEqual([], document.get_unrecognized_lines())
