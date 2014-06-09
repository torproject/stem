"""
Unit tests for the NetworkStatusDocumentV2 of stem.descriptor.networkstatus.
"""

import datetime
import unittest

import stem.descriptor

from test.mocking import get_network_status_document_v2, NETWORK_STATUS_DOCUMENT_HEADER_V2, NETWORK_STATUS_DOCUMENT_FOOTER_V2

from test.unit.descriptor import get_resource


class TestNetworkStatusDocument(unittest.TestCase):
  def test_consensus_v2(self):
    """
    Checks that version 2 consensus documents are properly parsed.
    """

    expected_signing_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOcrht/y5rkaahfX7sMe2qnpqoPibsjTSJaDvsUtaNP/Bq0MgNDGOR48
rtwfqTRff275Edkp/UYw3G3vSgKCJr76/bqOHCmkiZrnPV1zxNfrK18gNw2Cxre0
nTA+fD8JQqpPtb8b0SnG9kwy75eS//sRu7TErie2PzGMxrf9LH0LAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_signature = """-----BEGIN SIGNATURE-----
2nXCxVje3wzn6HrIFRNMc0nc48AhMVpHZyPwRKGXkuYfTQG55uvwQDaFgJHud4RT
27QhWltau3K1evhnzhKcpbTXwkVv1TBYJSzL6rEeAn8cQ7ZiCyqf4EJCaNcem3d2
TpQQk3nNQF8z6UIvdlvP+DnJV4izWVkQEZgUZgIVM0E=
-----END SIGNATURE-----"""

    with open(get_resource('cached-consensus-v2'), 'rb') as descriptor_file:
      descriptor_file.readline()  # strip header
      document = stem.descriptor.networkstatus.NetworkStatusDocumentV2(descriptor_file.read())

      self.assertEquals(2, document.version)
      self.assertEquals('18.244.0.114', document.hostname)
      self.assertEquals('18.244.0.114', document.address)
      self.assertEquals(80, document.dir_port)
      self.assertEquals('719BE45DE224B607C53707D0E2143E2D423E74CF', document.fingerprint)
      self.assertEquals('arma at mit dot edu', document.contact)
      self.assertEquals(expected_signing_key, document.signing_key)

      self.assertEquals(67, len(document.client_versions))
      self.assertEquals('0.0.9rc2', document.client_versions[0])
      self.assertEquals('0.1.1.10-alpha-cvs', document.client_versions[-1])

      self.assertEquals(67, len(document.server_versions))
      self.assertEquals('0.0.9rc2', document.server_versions[0])
      self.assertEquals('0.1.1.10-alpha-cvs', document.server_versions[-1])

      self.assertEquals(datetime.datetime(2005, 12, 16, 0, 13, 46), document.published)
      self.assertEquals(['Names', 'Versions'], document.options)
      self.assertEquals('moria2', document.signing_authority)
      self.assertEquals(expected_signature, document.signature)
      self.assertEquals([], document.get_unrecognized_lines())

      self.assertEqual(3, len(document.routers))

      router1 = document.routers['719BE45DE224B607C53707D0E2143E2D423E74CF']
      self.assertEquals('moria2', router1.nickname)
      self.assertEquals('719BE45DE224B607C53707D0E2143E2D423E74CF', router1.fingerprint)
      self.assertEquals('B7F3F0975B87889DD1285FD57A1B1BB617F65432', router1.digest)
      self.assertEquals(datetime.datetime(2005, 12, 15, 6, 57, 18), router1.published)
      self.assertEquals('18.244.0.114', router1.address)
      self.assertEquals(443, router1.or_port)
      self.assertEquals(80, router1.dir_port)
      self.assertEquals(set(['Authority', 'Fast', 'Named', 'Running', 'Valid', 'V2Dir']), set(router1.flags))

      router2 = document.routers['0928BA467056C4A689FEE4EF5D71482B6289C3D5']
      self.assertEquals('stnv', router2.nickname)
      self.assertEquals('0928BA467056C4A689FEE4EF5D71482B6289C3D5', router2.fingerprint)
      self.assertEquals('22D1A7ED4199BDA7ED6C416EECD769C18E1F2A5A', router2.digest)
      self.assertEquals(datetime.datetime(2005, 12, 15, 16, 24, 42), router2.published)
      self.assertEquals('84.16.236.173', router2.address)
      self.assertEquals(9001, router2.or_port)
      self.assertEquals(None, router2.dir_port)
      self.assertEquals(set(['Named', 'Valid']), set(router2.flags))

      router3 = document.routers['09E8582FF0E6F85E2B8E41C0DC0B9C9DC46E6968']
      self.assertEquals('nggrplz', router3.nickname)
      self.assertEquals('09E8582FF0E6F85E2B8E41C0DC0B9C9DC46E6968', router3.fingerprint)
      self.assertEquals('B302C2B01C94F398E3EF38939526B0651F824DD6', router3.digest)
      self.assertEquals(datetime.datetime(2005, 12, 15, 23, 25, 50), router3.published)
      self.assertEquals('194.109.109.109', router3.address)
      self.assertEquals(9001, router3.or_port)
      self.assertEquals(None, router3.dir_port)
      self.assertEquals(set(['Fast', 'Stable', 'Running', 'Valid']), set(router3.flags))

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
