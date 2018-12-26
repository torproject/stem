"""
Unit tests for the KeyCertificate of stem.descriptor.networkstatus.
"""

import datetime
import unittest

import stem.descriptor
import test.require

from stem.descriptor.networkstatus import KeyCertificate
from test.unit.descriptor import get_resource


class TestKeyCertificate(unittest.TestCase):
  def test_minimal(self):
    """
    Parses a minimal key certificate.
    """

    certificate = KeyCertificate.create()

    self.assertEqual(3, certificate.version)
    self.assertEqual(None, certificate.address)
    self.assertEqual(None, certificate.dir_port)
    self.assertEqual(40, len(certificate.fingerprint))
    self.assertEqual(None, certificate.crosscert)
    self.assertEqual([], certificate.get_unrecognized_lines())

  def test_real_certificates(self):
    """
    Checks that key certificates from chutney can be properly parsed.
    """

    expected_identity_key = """\
-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAxfTHG1b3Sxe8n3JQ/nIk4+1/chj7+jAyLLK+WrEBiP1vnDxTXMuo
x26ntWEjOaxjtKB12k5wMQW94/KvE754Gn98uQRFBHqLkrS4hUnn4/MqiBQVd2y3
UtE6KDSRhJZ5LfFH+dCKwu5+695PyJp/pfCUSOyPj0HQbFOnAOqdHPok8dtdfsy0
LaI7ycpzqAalzgrlwFP5KwwLtL+VapUGN4QOZlIXgL4W5e7OAG42lZhHt0b7/zdt
oIegZM1y8tK2l75ijqsvbetddQcFlnVaYzNwlQAUIZuxJOGfnPfTo+WrjCgrK2ur
ed5NiQMrEbZn5uCUscs+xLlKl4uKW0XXo1EIL45yBrVbmlP6V3/9diTHk64W9+m8
2G4ToDyH8J7LvnYPsmD0cCaQEceebxYVlmmwgqdORH/ixbeGF7JalTwtWBQYo2r0
VZAqjRwxR9dri6m1MIpzmzWmrbXghZ1IzJEL1rpB0okA/bE8AUGRx61eKnbI415O
PmO06JMpvkxxAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_signing_key = """\
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvzugxJl1gc7BgXarBO5IWejNZC30U1xVjZ/myQTzxtiKkPU0agQh
sPqn4vVsaW6ZnWjJ2pSOq0/jg8WgFyGHGQ9cG8tv2TlpObeb/tI7iANxWx+MXJAh
/CnFDBQ1ifKntJrs2IcRKMivfobqaHAL3Pz93noLWOTQunWjZ8D6kovYvUXe+yUQ
tZEROrmXJx7ZIIJF6BNKYBTc+iEkYtkWlJVs0my7yP/bbS075QyBsr6CfT+O2yU4
mgIg43QuqcFRbjyUvGI/gap06QNlB6yj8pqeE5rWo++5EpEvMK76fK6ymYuTN2SN
Oil+Fo7qgG8UP/fv0GelSz6Tk7pBoeHJlQIDAQAB
-----END RSA PUBLIC KEY-----"""

    expected_crosscert = """\
-----BEGIN ID SIGNATURE-----
Oz+rvXDzlxLgQSb3nS5/4hrHVWgGCy0OnuNmFsyw8bi2eBst5Yj79dQ+D25giZke
81FRGIFU4eS6dshB+pJ+z0hc9ozlRTYh/qevY6l6o0amvuhHyk/cQXrh8oYU9Ihe
XQ1yVItvxC24HENsoGIGbr5uxc85FOcNs+R9qTLYA/56TjvAU4WUje3nTZE1awml
lj/Y6DM7ruMF6UoYJZPTklukZ+XHZg4Z2eE55e/oIaD7bfU/lFWU/alMyTV/J5oT
sxaD2XBLBScYiKypUmgrZ50W4ZqsXaYk76ClrudZnDbce+FuugVxok+jKYGjMu75
2es2ucuik7iuO7QPdPIXfg==
-----END ID SIGNATURE-----"""

    expected_key_cert = """\
-----BEGIN SIGNATURE-----
I86FTQ5ZyCZUzm19HVAQWByrrRgUmddoRBfNiCj0iTGN3kdIq9OfuNLhWAqz71xP
8Nn0Vun8Uj3/vBq/odIFpnngL3mKI6OEKcNDr0D5hEV9Yjrxe8msMoaUZT+LHzUW
1q3pzxfMx6EmlSilMhuzSsa4YEbXMZzMqASKANSJHo2fzUkzQOpPw2SlWSTIgyqw
wAOB6QOvFfP3c0NTwxXrYE/iT+r90wZBuzS+v7r9B94alNAkE1KZQKnq2QTTIznP
iF9LWMsZcMHCjoTxszK4jF4MRMN/S4Xl8yQo0/z6FoqBz4RIXzFtJoG/rbXdKfkE
nJK9iEhaZbS1IN0o+uIGtvOm2rQSu9gS8merurr5GDSK3szjesPVJuF00mCNgOx4
hAYPN9N8HAL4zGE/l1UM7BGg3L84A0RMpDxnpXePd9mlHLhl4UV2lrkkf8S9Z6fX
PPc3r7zKlL/jEGHwz+C7kE88HIvkVnKLLn//40b6HxitHSOCkZ1vtp8YyXae6xnU
-----END SIGNATURE-----"""

    with open(get_resource('cached-certs'), 'rb') as cert_file:
      cert = next(stem.descriptor.parse_file(cert_file, 'dir-key-certificate-3 1.0'))
      self.assertEqual(3, cert.version)
      self.assertEqual('127.0.0.1', cert.address)
      self.assertEqual(7000, cert.dir_port)
      self.assertEqual('BCB380A633592C218757BEE11E630511A485658A', cert.fingerprint)
      self.assertEqual(expected_identity_key, cert.identity_key)
      self.assertEqual(datetime.datetime(2017, 5, 25, 4, 45, 52), cert.published)
      self.assertEqual(datetime.datetime(2018, 5, 25, 4, 45, 52), cert.expires)
      self.assertEqual(expected_signing_key, cert.signing_key)
      self.assertEqual(expected_crosscert, cert.crosscert)
      self.assertEqual(expected_key_cert, cert.certification)
      self.assertEqual('@type dir-key-certificate-3 1.0', str(cert.type_annotation()))
      self.assertEqual([], cert.get_unrecognized_lines())

  def test_metrics_certificate(self):
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

    with open(get_resource('metrics_cert'), 'rb') as cert_file:
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

  @test.require.cryptography
  def test_descriptor_signing(self):
    self.assertRaisesWith(NotImplementedError, 'Signing of KeyCertificate not implemented', KeyCertificate.create, sign = True)

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    certificate = KeyCertificate.create({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], certificate.get_unrecognized_lines())

  def test_first_and_last_lines(self):
    """
    Includes a non-mandatory field before the 'dir-key-certificate-version'
    line or after the 'dir-key-certification' line.
    """

    content = KeyCertificate.content()

    for cert_text in (b'dir-address 127.0.0.1:80\n' + content,
                      content + b'\ndir-address 127.0.0.1:80'):
      self.assertRaises(ValueError, KeyCertificate, cert_text, True)

      certificate = KeyCertificate(cert_text, False)
      self.assertEqual('127.0.0.1', certificate.address)
      self.assertEqual(80, certificate.dir_port)

  def test_missing_fields(self):
    """
    Parse a key certificate where a mandatory field is missing.
    """

    mandatory_fields = (
      'dir-key-certificate-version',
      'fingerprint',
      'dir-key-published',
      'dir-key-expires',
      'dir-identity-key',
      'dir-signing-key',
      'dir-key-certification',
    )

    for excluded_field in mandatory_fields:
      content = KeyCertificate.content(exclude = (excluded_field,))
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)

      if excluded_field == 'fingerprint':
        self.assertEqual(3, certificate.version)
      else:
        self.assertEqual(40, len(certificate.fingerprint))

  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """

    certificate = KeyCertificate.create({'dir-key-published': '2011-11-28 21:51:04\n\n\n'})
    self.assertEqual(datetime.datetime(2011, 11, 28, 21, 51, 4), certificate.published)

  def test_version(self):
    """
    Parses the dir-key-certificate-version field, including trying to handle a
    different certificate version with the v3 parser.
    """

    certificate = KeyCertificate.create({'dir-key-certificate-version': '3'})
    self.assertEqual(3, certificate.version)

    content = KeyCertificate.content({'dir-key-certificate-version': '4'})
    self.assertRaises(ValueError, KeyCertificate, content, True)
    self.assertEqual(4, KeyCertificate(content, False).version)

    content = KeyCertificate.content({'dir-key-certificate-version': 'boo'})
    self.assertRaises(ValueError, KeyCertificate, content, True)
    self.assertEqual(None, KeyCertificate(content, False).version)

  def test_dir_address(self):
    """
    Parses the dir-address field.
    """

    certificate = KeyCertificate.create({'dir-address': '127.0.0.1:80'})
    self.assertEqual('127.0.0.1', certificate.address)
    self.assertEqual(80, certificate.dir_port)

    test_values = (
      (''),
      ('   '),
      ('127.0.0.1'),
      ('127.0.0.1:'),
      ('80'),
      (':80'),
      ('127.0.0.1a:80'),
      ('127.0.0.1:80a'),
    )

    for test_value in test_values:
      content = KeyCertificate.content({'dir-address': test_value})
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)
      self.assertEqual(None, certificate.address)
      self.assertEqual(None, certificate.dir_port)

  def test_fingerprint(self):
    """
    Parses the fingerprint field.
    """

    test_values = (
      '',
      '   ',
      '27B6B5996C426270A5C95488AA5BCEB6BCC8695',
      '27B6B5996C426270A5C95488AA5BCEB6BCC869568',
    )

    for test_value in test_values:
      content = KeyCertificate.content({'fingerprint': test_value})
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)
      self.assertEqual(None, certificate.fingerprint)

  def test_time_fields(self):
    """
    Parses the dir-key-published and dir-key-expires fields, which both have
    datetime content.
    """

    test_values = (
      '',
      '   ',
      '2012-12-12',
      '2012-12-12 01:01:',
      '2012-12-12 01:a1:01',
    )

    for field, attr in (('dir-key-published', 'published'), ('dir-key-expires', 'expires')):
      for test_value in test_values:
        content = KeyCertificate.content({field: test_value})
        self.assertRaises(ValueError, KeyCertificate, content, True)

        certificate = KeyCertificate(content, False)
        self.assertEqual(None, getattr(certificate, attr))

  def test_key_blocks(self):
    """
    Parses the dir-identity-key, dir-signing-key, dir-key-crosscert, and
    dir-key-certification fields which all just have signature content.
    """

    # the only non-mandatory field that we haven't exercised yet is dir-key-crosscert

    certificate = KeyCertificate.create({'dir-key-crosscert': '\n-----BEGIN ID SIGNATURE-----%s-----END ID SIGNATURE-----' % stem.descriptor.CRYPTO_BLOB})
    self.assertTrue(stem.descriptor.CRYPTO_BLOB in certificate.crosscert)

    test_value = '\n-----BEGIN ID SIGNATURE-----%s-----END UGABUGA SIGNATURE-----' % stem.descriptor.CRYPTO_BLOB

    for field, attr in (('dir-identity-key', 'identity_key'),
                        ('dir-signing-key', 'signing_key'),
                        ('dir-key-crosscert', 'crosscert'),
                        ('dir-key-certification', 'certification')):
      content = KeyCertificate.content({field: test_value})
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)
      self.assertEqual(None, getattr(certificate, attr))

  def test_wrong_block_type(self):
    """
    Checks that we validate the type of crypto content we receive.
    """

    content = KeyCertificate.content({'dir-identity-key': '\n-----BEGIN MD5SUM-----%s-----END MD5SUM-----' % stem.descriptor.CRYPTO_BLOB})
    self.assertRaises(ValueError, KeyCertificate, content, True)
