"""
Unit tests for the NetworkStatusDocumentV2 of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from test.mocking import get_network_status_document_v2, NETWORK_STATUS_DOCUMENT_HEADER_V2, NETWORK_STATUS_DOCUMENT_FOOTER_V2


class TestNetworkStatusDocument(unittest.TestCase):
  def test_minimal_document(self):
    """
    Parses a minimal v2 network status document.
    """

    document = get_network_status_document_v2()

    self.assertEquals({}, document.routers)
    self.assertEquals(2, document.version)
    self.assertEquals('18.244.0.114', document.hostname)
    self.assertEquals('18.244.0.114', document.address)
    self.assertEquals(80, document.dir_port)
    self.assertEquals('719BE45DE224B607C53707D0E2143E2D423E74CF', document.fingerprint)
    self.assertEquals('arma at mit dot edu', document.contact)
    self.assertEquals(NETWORK_STATUS_DOCUMENT_HEADER_V2[5][1][1:], document.signing_key)
    self.assertEquals([], document.client_versions)
    self.assertEquals([], document.server_versions)
    self.assertEquals(datetime.datetime(2005, 12, 16, 0, 13, 46), document.published)
    self.assertEquals([], document.options)
    self.assertEquals('moria2', document.signing_authority)
    self.assertEquals(NETWORK_STATUS_DOCUMENT_FOOTER_V2[0][1][7:], document.signature)
