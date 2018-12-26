"""
Unit tests for the BridgeNetworkStatusDocument of stem.descriptor.networkstatus.
"""

import datetime
import unittest

import stem.descriptor

from stem.descriptor.networkstatus import BridgeNetworkStatusDocument

from test.unit.descriptor import get_resource

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
  def test_metrics_bridge_consensus(self):
    """
    Checks if the bridge documents from Metrics are parsed properly.
    """

    consensus_path = get_resource('bridge_network_status')

    with open(consensus_path, 'rb') as descriptor_file:
      router = next(stem.descriptor.parse_file(descriptor_file))
      self.assertEqual('Unnamed', router.nickname)
      self.assertEqual('0014A2055278DB3EB0E59EA701741416AF185558', router.fingerprint)
      self.assertEqual('148EF8685B8D259650AE0967D1FF8E6A870C7743', router.digest)
      self.assertEqual(datetime.datetime(2012, 5, 31, 15, 57, 0), router.published)
      self.assertEqual('10.97.236.247', router.address)
      self.assertEqual(443, router.or_port)
      self.assertEqual(None, router.dir_port)

  def test_empty_document(self):
    """
    Parse a document without any router status entries.
    """

    document = BridgeNetworkStatusDocument(b'published 2012-06-01 04:07:04')
    self.assertEqual(datetime.datetime(2012, 6, 1, 4, 7, 4), document.published)
    self.assertEqual({}, document.routers)
    self.assertEqual([], document.get_unrecognized_lines())
    self.assertEqual('@type bridge-network-status 1.0', str(document.type_annotation()))

  def test_document(self):
    """
    Parse a document with router status entries.
    """

    document = BridgeNetworkStatusDocument(DOCUMENT)
    self.assertEqual(datetime.datetime(2012, 6, 1, 4, 7, 4), document.published)

    self.assertEqual(2, len(document.routers))
    self.assertEqual(set(['Unnamed', 'TolFuin']), set([desc.nickname for desc in document.routers.values()]))
    self.assertEqual([], document.get_unrecognized_lines())
