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

  def test_metrics_cert(self):
    """
    Checks if consensus documents from Metrics are parsed properly.
    """

    expected_identity_key = """-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEA7cZXvDRxfjDYtr9/9UsQ852+6cmHMr8VVh8GkLwbq3RzqjkULwQ2
R9mFvG4FnqMcMKXi62rYYA3fZL1afhT804cpvyp/D3dPM8QxW88fafFAgIFP4LiD
0JYjnF8cva5qZ0nzlWnMXLb32IXSvsGSE2FRyAV0YN9a6k967LSgCfUnZ+IKMezW
1vhL9YK4QIfsDowgtVsavg63GzGmA7JvZmn77+/J5wKz11vGr7Wttf8XABbH2taX
O9j/KGBOX2OKhoF3mXfZSmUO2dV9NMwtkJ7zD///Ny6sfApWV6kVP4O9TdG3bAsl
+fHCoCKgF/jAAWzh6VckQTOPzQZaH5aMWfXrDlzFWg17MjonI+bBTD2Ex2pHczzJ
bN7coDMRH2SuOXv8wFf27KdUxZ/GcrXSRGzlRLygxqlripUanjVGN2JvrVQVr0kz
pjNjiZl2z8ZyZ5d4zQuBi074JPGgx62xAstP37v1mPw14sIWfLgY16ewYuS5bCxV
lyS28jsPht9VAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_signing_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOeE3Qr1Km97gTgiB3io0EU0fqHW2ESMXVHeQuNDtCWBa0XSCEG6gx4B
ZkkHjfVWqGQ7TmmzjYP9L9uCgtoKfhSvJA2w9NUMtMl8sgZmF4lcGpXXvGY9a566
Bn+3wP0lMhb/I8CPVPX+NWEjgl1noZxo1C59SO/iALGQOpxRYgmbAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_key_cert = """-----BEGIN SIGNATURE-----
asvWwaMq34OfHoWUhAwh4+JDOuEUZJVIHQnedOYfQH8asS2QvW3Ma93OhrwVOC6b
FyKmTJmJsl0MJGiC7tcEOlL6knsKE4CsuIw/PEcu2Rnm+R9zWxQuMYiHvGQMoDxl
giOhLLs4LlzAAJlbfbd3hjF4STVAtTwmxYuIjb1Mq/JfAsx/wH3TLXgVZwj32w9s
zUd9KZwwLzFiiHpC+U7zh6+wRsZfo2tlpmcaP1dTSINgVbdzPJ/DOUlx9nwTCBsE
AQpUx2DpAikwrpw0zDqpQvYulcQlNLWFN/y/PkmiK8mIJk0OBMiQA7JgqWamnnk4
PwqaGv483LkBF+25JFGJmnUVve3RMc+s61+2kBcjfUMed4QaHkeCMHqlRqpfQVkk
RY22NXCwrJvSMEwiy7acC8FGysqwHRyE356+Rw6TB43g3Tno9KaHEK7MHXjSHwNs
GM9hAsAMRX9Ogqhq5UjDNqEsvDKuyVeyh7unSZEOip9Zr6K/+7VsVPNb8vfBRBjo
-----END SIGNATURE-----"""

    cert_path = get_resource('metrics_cert')

    with open(cert_path, 'rb') as cert_file:
      cert = next(stem.descriptor.parse_file(cert_file))
      self.assertEqual(3, cert.version)
      self.assertEqual(None, cert.address)
      self.assertEqual(None, cert.dir_port)
      self.assertEqual('14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4', cert.fingerprint)
      self.assertEqual(expected_identity_key, cert.identity_key)
      self.assertEqual(datetime.datetime(2008, 5, 9, 21, 13, 26), cert.published)
      self.assertEqual(datetime.datetime(2009, 5, 9, 21, 13, 26), cert.expires)
      self.assertEqual(expected_signing_key, cert.signing_key)
      self.assertEqual(None, cert.crosscert)
      self.assertEqual(expected_key_cert, cert.certification)
      self.assertEqual([], cert.get_unrecognized_lines())

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
