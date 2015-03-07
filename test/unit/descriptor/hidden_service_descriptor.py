"""
Unit tests for stem.descriptor.hidden_service_descriptor.
"""

import datetime
import unittest

import stem.descriptor
import stem.prereq

import test.runner

from test.mocking import CRYPTO_BLOB, get_hidden_service_descriptor
from test.unit.descriptor import get_resource

from stem.descriptor.hidden_service_descriptor import (
  REQUIRED_FIELDS,
  DecryptionFailure,
  HiddenServiceDescriptor,
)

MESSAGE_BLOCK = """
-----BEGIN MESSAGE-----
%s
-----END MESSAGE-----\
"""

EXPECTED_DDG_PERMANENT_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJ/SzzgrXPxTlFrKVhXh3buCWv2QfcNgncUpDpKouLn3AtPH5Ocys0jE
aZSKdvaiQ62md2gOwj4x61cFNdi05tdQjS+2thHKEm/KsB9BGLSLBNJYY356bupg
I5gQozM65ENelfxYlysBjJ52xSDBd8C4f/p9umdzaaaCmzXG/nhzAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECTED_DDG_INTRODUCTION_POINTS_ENCODED = """\
-----BEGIN MESSAGE-----
aW50cm9kdWN0aW9uLXBvaW50IGl3a2k3N3h0YnZwNnF2ZWRmcndkem5jeHMzY2th
eWV1CmlwLWFkZHJlc3MgMTc4LjYyLjIyMi4xMjkKb25pb24tcG9ydCA0NDMKb25p
b24ta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFL
OTRCRVlJSFo0S2RFa2V5UGhiTENwUlc1RVNnKzJXUFFock00eXVLWUd1cTh3Rldn
dW1aWVI5CmsvV0EvL0ZZWE1CejBiQitja3Vacy9ZdTluSytITHpwR2FwVjBjbHN0
NEdVTWNCSW5VQ3pDY3BqSlRRc1FEZ20KMy9ZM2NxaDBXNTVnT0NGaG9tUTQvMVdP
WWc3WUNqazRYWUhKRTIwT2RHMkxsNXpvdEs2ZkFnTUJBQUU9Ci0tLS0tRU5EIFJT
QSBQVUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVC
TElDIEtFWS0tLS0tCk1JR0pBb0dCQUpYbUpiOGxTeWRNTXFDZ0NnZmd2bEIyRTVy
cGQ1N2t6L0FxZzcvZDFIS2MzK2w1UW9Vdkh5dXkKWnNBbHlrYThFdTUzNGhsNDFv
cUVLcEFLWWNNbjFUTTB2cEpFR05WT2MrMDVCSW54STloOWYwTWcwMVBEMHRZdQpH
Y0xIWWdCemNyZkVtS3dNdE04V0VtY01KZDduMnVmZmFBdko4NDZXdWJiZVY3TVcx
WWVoQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1
Y3Rpb24tcG9pbnQgZW00Z2prNmVpaXVhbGhtbHlpaWZyemM3bGJ0cnNiaXAKaXAt
YWRkcmVzcyA0Ni40LjE3NC41Mgpvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkKLS0t
LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUxCbWhkRjV3SHhI
cnBMU21qQVpvdHR4MjIwKzk5NUZkTU9PdFpOalJ3MURCU3ByVVpacXR4V2EKUDhU
S3BIS3p3R0pLQ1ZZSUlqN2xvaGJ2OVQ5dXJtbGZURTA1VVJHZW5ab2lmT0ZOejNZ
d01KVFhTY1FFQkoxMAo5aVdOTERUc2tMekRLQ0FiR2hibi9NS3dPZllHQmhOVGxq
ZHlUbU5ZNUVDUmJSempldjl2QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL
RVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t
LS0KTUlHSkFvR0JBTXhNSG9BbXJiVU1zeGlJQ3AzaVRQWWdobjBZdWVLSHgyMTl3
dThPL1E1MVF5Y1ZWTHBYMjdkMQpoSlhrUEIzM1hRQlhzQlM3U3hzU3NTQ1EzR0V1
clFKN0d1QkxwWUlSL3Zxc2FrRS9sOHdjMkNKQzVXVWh5RkZrCisxVFdJVUk1dHhu
WEx5V0NSY0tEVXJqcWRvc0RhRG9zZ0hGZzIzTW54K3hYY2FRL2ZyQi9BZ01CQUFF
PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2lu
dCBqcWhmbDM2NHgzdXBlNmxxbnhpem9sZXdsZnJzdzJ6eQppcC1hZGRyZXNzIDYy
LjIxMC44Mi4xNjkKb25pb24tcG9ydCA0NDMKb25pb24ta2V5Ci0tLS0tQkVHSU4g
UlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFQVWtxeGdmWWR3MFBtL2c2TWJo
bVZzR0tsdWppZm1raGRmb0VldXpnbyt3bkVzR3Z3VWVienJ6CmZaSlJ0MGNhWEZo
bkNHZ1FEMklnbWFyVWFVdlAyNGZYby80bVl6TGNQZUk3Z1puZXVBUUpZdm05OFl2
OXZPSGwKTmFNL1d2RGtDc0ozR1ZOSjFIM3dMUFFSSTN2N0tiTnVjOXRDT1lsL3Iw
OU9oVmFXa3phakFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
c2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pB
b0dCQUxieDhMZXFSb1Avcjl3OWhqd0Q0MVlVbTdQbzY5N3hSdHl0RjBNY3lMQ1M3
R1JpVVluamk3S1kKZmVwWGR2Ti9KbDVxUUtISUJiNjAya3VPVGwwcE44UStZZUZV
U0lJRGNtUEJMcEJEaEgzUHZyUU1jR1ZhaU9XSAo4dzBITVpDeGd3QWNDQzUxdzVW
d2l1bXhFSk5CVmNac094MG16TjFDbG95KzkwcTBsRlhMQWdNQkFBRT0KLS0tLS1F
TkQgUlNBIFBVQkxJQyBLRVktLS0tLQoK
-----END MESSAGE-----\
"""

EXPECTED_DDG_INTRODUCTION_POINTS_CONTENT = b"""\
introduction-point iwki77xtbvp6qvedfrwdzncxs3ckayeu
ip-address 178.62.222.129
onion-port 443
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK94BEYIHZ4KdEkeyPhbLCpRW5ESg+2WPQhrM4yuKYGuq8wFWgumZYR9
k/WA//FYXMBz0bB+ckuZs/Yu9nK+HLzpGapV0clst4GUMcBInUCzCcpjJTQsQDgm
3/Y3cqh0W55gOCFhomQ4/1WOYg7YCjk4XYHJE20OdG2Ll5zotK6fAgMBAAE=
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJXmJb8lSydMMqCgCgfgvlB2E5rpd57kz/Aqg7/d1HKc3+l5QoUvHyuy
ZsAlyka8Eu534hl41oqEKpAKYcMn1TM0vpJEGNVOc+05BInxI9h9f0Mg01PD0tYu
GcLHYgBzcrfEmKwMtM8WEmcMJd7n2uffaAvJ846WubbeV7MW1YehAgMBAAE=
-----END RSA PUBLIC KEY-----
introduction-point em4gjk6eiiualhmlyiifrzc7lbtrsbip
ip-address 46.4.174.52
onion-port 443
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALBmhdF5wHxHrpLSmjAZottx220+995FdMOOtZNjRw1DBSprUZZqtxWa
P8TKpHKzwGJKCVYIIj7lohbv9T9urmlfTE05URGenZoifOFNz3YwMJTXScQEBJ10
9iWNLDTskLzDKCAbGhbn/MKwOfYGBhNTljdyTmNY5ECRbRzjev9vAgMBAAE=
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMxMHoAmrbUMsxiICp3iTPYghn0YueKHx219wu8O/Q51QycVVLpX27d1
hJXkPB33XQBXsBS7SxsSsSCQ3GEurQJ7GuBLpYIR/vqsakE/l8wc2CJC5WUhyFFk
+1TWIUI5txnXLyWCRcKDUrjqdosDaDosgHFg23Mnx+xXcaQ/frB/AgMBAAE=
-----END RSA PUBLIC KEY-----
introduction-point jqhfl364x3upe6lqnxizolewlfrsw2zy
ip-address 62.210.82.169
onion-port 443
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAPUkqxgfYdw0Pm/g6MbhmVsGKlujifmkhdfoEeuzgo+wnEsGvwUebzrz
fZJRt0caXFhnCGgQD2IgmarUaUvP24fXo/4mYzLcPeI7gZneuAQJYvm98Yv9vOHl
NaM/WvDkCsJ3GVNJ1H3wLPQRI3v7KbNuc9tCOYl/r09OhVaWkzajAgMBAAE=
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALbx8LeqRoP/r9w9hjwD41YUm7Po697xRtytF0McyLCS7GRiUYnji7KY
fepXdvN/Jl5qQKHIBb602kuOTl0pN8Q+YeFUSIIDcmPBLpBDhH3PvrQMcGVaiOWH
8w0HMZCxgwAcCC51w5VwiumxEJNBVcZsOx0mzN1Cloy+90q0lFXLAgMBAAE=
-----END RSA PUBLIC KEY-----

"""

EXPECTED_DDG_SIGNATURE = """\
-----BEGIN SIGNATURE-----
VKMmsDIUUFOrpqvcQroIZjDZTKxqNs88a4M9Te8cR/ZvS7H2nffv6iQs0tom5X4D
4Dy4iZiy+pwYxdHfaOxmdpgMCRvgPb34MExWr5YemH0QuGtnlp5Wxr8GYaAQVuZX
cZjQLW0juUYCbgIGdxVEBnlEt2rgBSM9+1oR7EAfV1U=
-----END SIGNATURE-----\
"""

EXPECT_POINT_1_ONION_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAK94BEYIHZ4KdEkeyPhbLCpRW5ESg+2WPQhrM4yuKYGuq8wFWgumZYR9
k/WA//FYXMBz0bB+ckuZs/Yu9nK+HLzpGapV0clst4GUMcBInUCzCcpjJTQsQDgm
3/Y3cqh0W55gOCFhomQ4/1WOYg7YCjk4XYHJE20OdG2Ll5zotK6fAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECT_POINT_1_SERVICE_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJXmJb8lSydMMqCgCgfgvlB2E5rpd57kz/Aqg7/d1HKc3+l5QoUvHyuy
ZsAlyka8Eu534hl41oqEKpAKYcMn1TM0vpJEGNVOc+05BInxI9h9f0Mg01PD0tYu
GcLHYgBzcrfEmKwMtM8WEmcMJd7n2uffaAvJ846WubbeV7MW1YehAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECT_POINT_2_ONION_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALBmhdF5wHxHrpLSmjAZottx220+995FdMOOtZNjRw1DBSprUZZqtxWa
P8TKpHKzwGJKCVYIIj7lohbv9T9urmlfTE05URGenZoifOFNz3YwMJTXScQEBJ10
9iWNLDTskLzDKCAbGhbn/MKwOfYGBhNTljdyTmNY5ECRbRzjev9vAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECT_POINT_2_SERVICE_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMxMHoAmrbUMsxiICp3iTPYghn0YueKHx219wu8O/Q51QycVVLpX27d1
hJXkPB33XQBXsBS7SxsSsSCQ3GEurQJ7GuBLpYIR/vqsakE/l8wc2CJC5WUhyFFk
+1TWIUI5txnXLyWCRcKDUrjqdosDaDosgHFg23Mnx+xXcaQ/frB/AgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECT_POINT_3_ONION_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAPUkqxgfYdw0Pm/g6MbhmVsGKlujifmkhdfoEeuzgo+wnEsGvwUebzrz
fZJRt0caXFhnCGgQD2IgmarUaUvP24fXo/4mYzLcPeI7gZneuAQJYvm98Yv9vOHl
NaM/WvDkCsJ3GVNJ1H3wLPQRI3v7KbNuc9tCOYl/r09OhVaWkzajAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECT_POINT_3_SERVICE_KEY = """\
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALbx8LeqRoP/r9w9hjwD41YUm7Po697xRtytF0McyLCS7GRiUYnji7KY
fepXdvN/Jl5qQKHIBb602kuOTl0pN8Q+YeFUSIIDcmPBLpBDhH3PvrQMcGVaiOWH
8w0HMZCxgwAcCC51w5VwiumxEJNBVcZsOx0mzN1Cloy+90q0lFXLAgMBAAE=
-----END RSA PUBLIC KEY-----\
"""

EXPECTED_BASIC_AUTH_INTRODUCTION_POINTS_ENCODED = """\
-----BEGIN MESSAGE-----
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
-----END MESSAGE-----\
"""


class TestHiddenServiceDescriptor(unittest.TestCase):
  def test_for_duckduckgo_with_validation(self):
    """
    Parse duckduckgo's descriptor.
    """

    descriptor_file = open(get_resource('hidden_service_duckduckgo'), 'rb')
    desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor 1.0', validate = True))
    self._assert_matches_duckduckgo(desc)

  def test_for_duckduckgo_without_validation(self):
    """
    Parse duckduckgo's descriptor
    """

    descriptor_file = open(get_resource('hidden_service_duckduckgo'), 'rb')
    desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor 1.0', validate = False))
    self._assert_matches_duckduckgo(desc)

  def test_for_facebook(self):
    """
    Parse facebook's descriptor.
    """

    descriptor_file = open(get_resource('hidden_service_facebook'), 'rb')

    desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor 1.0', validate = True))
    self.assertEqual('utjk4arxqg6s6zzo7n6cjnq6ot34udhr', desc.descriptor_id)
    self.assertEqual(2, desc.version)
    self.assertEqual('6355jaerje3bqozopwq2qmpf4iviizdn', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2014, 10, 31, 23, 0, 0), desc.published)
    self.assertEqual([2, 3], desc.protocol_versions)

  def test_with_basic_auth(self):
    """
    Parse a descriptor with introduction-points encrypted with basic auth.
    """

    if not stem.prereq.is_crypto_available():
      return test.runner.skip(self, 'requires pycrypto')

    descriptor_file = open(get_resource('hidden_service_basic_auth'), 'rb')

    desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor 1.0', validate = True))
    self.assertEqual('yfmvdrkdbyquyqk5vygyeylgj2qmrvrd', desc.descriptor_id)
    self.assertEqual(2, desc.version)
    self.assertEqual('fluw7z3s5cghuuirq3imh5jjj5ljips6', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2015, 2, 24, 20, 0, 0), desc.published)
    self.assertEqual([2, 3], desc.protocol_versions)
    self.assertEqual(EXPECTED_BASIC_AUTH_INTRODUCTION_POINTS_ENCODED, desc.introduction_points_encoded)
    self.assertEqual([], desc.introduction_points_auth)

    self.assertRaises(DecryptionFailure, desc.introduction_points)
    self.assertRaises(DecryptionFailure, desc.introduction_points, 'aCmx3qIvArbil8A0KM4KgQ==')

    introduction_points = desc.introduction_points('dCmx3qIvArbil8A0KM4KgQ==')
    self.assertEqual(3, len(introduction_points))

    point = introduction_points[0]
    self.assertEqual('hmtvoobwglmmec26alnvl7x7mgmmr7xv', point.identifier)
    self.assertEqual('195.154.82.88', point.address)
    self.assertEqual(443, point.port)
    self.assertTrue('MIGJAoGBANbPRD07T' in point.onion_key)
    self.assertTrue('MIGJAoGBAN+LAdZP/' in point.service_key)
    self.assertEqual([], point.intro_authentication)

    point = introduction_points[1]
    self.assertEqual('q5w6l2f4g5zw4rkr56fkyovbkkrnzcj5', point.identifier)
    self.assertEqual('37.252.190.133', point.address)
    self.assertEqual(9001, point.port)
    self.assertTrue('MIGJAoGBAKmsbKrtt' in point.onion_key)
    self.assertTrue('MIGJAoGBANwczLtzR' in point.service_key)
    self.assertEqual([], point.intro_authentication)

    point = introduction_points[2]
    self.assertEqual('qcvprvmvnjb4dfyqjtxskugniliwlrx3', point.identifier)
    self.assertEqual('193.11.114.45', point.address)
    self.assertEqual(9002, point.port)
    self.assertTrue('MIGJAoGBAM1ILL+7P' in point.onion_key)
    self.assertTrue('MIGJAoGBAM7B/cymp' in point.service_key)
    self.assertEqual([], point.intro_authentication)

  def test_with_stealth_auth(self):
    """
    Parse a descriptor with introduction-points encrypted with stealth auth.
    """

    if not stem.prereq.is_crypto_available():
      return test.runner.skip(self, 'requires pycrypto')

    descriptor_file = open(get_resource('hidden_service_stealth_auth'), 'rb')

    desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor 1.0', validate = True))
    self.assertEqual('ubf3xeibzlfil6s4larq6y5peup2z3oj', desc.descriptor_id)
    self.assertEqual(2, desc.version)
    self.assertEqual('jczvydhzetbpdiylj3d5nsnjvaigs7xm', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2015, 2, 24, 20, 0, 0), desc.published)
    self.assertEqual([2, 3], desc.protocol_versions)
    self.assertEqual([], desc.introduction_points_auth)

    self.assertRaises(DecryptionFailure, desc.introduction_points)
    self.assertRaises(DecryptionFailure, desc.introduction_points, 'aCmx3qIvArbil8A0KM4KgQ==')

    introduction_points = desc.introduction_points('dCmx3qIvArbil8A0KM4KgQ==')
    self.assertEqual(3, len(introduction_points))

    point = introduction_points[0]
    self.assertEqual('6h4bkedts3yz2exl3vu4lsyiwkjrx5ff', point.identifier)
    self.assertEqual('95.85.60.23', point.address)
    self.assertEqual(443, point.port)
    self.assertTrue('MIGJAoGBAMX5hO5hQ' in point.onion_key)
    self.assertTrue('MIGJAoGBAMNSjfydv' in point.service_key)
    self.assertEqual([], point.intro_authentication)

    point = introduction_points[1]
    self.assertEqual('4ghasjftsdfbbycafvlfx7czln3hrk53', point.identifier)
    self.assertEqual('178.254.55.101', point.address)
    self.assertEqual(9901, point.port)
    self.assertTrue('MIGJAoGBAL2v/KNEY' in point.onion_key)
    self.assertTrue('MIGJAoGBAOXiuIgBr' in point.service_key)
    self.assertEqual([], point.intro_authentication)

    point = introduction_points[2]
    self.assertEqual('76tsxvudxqx47gedk3tl5qpesdzrh6yh', point.identifier)
    self.assertEqual('193.11.164.243', point.address)
    self.assertEqual(9001, point.port)
    self.assertTrue('MIGJAoGBALca3zEoS' in point.onion_key)
    self.assertTrue('MIGJAoGBAL3rWIAQ6' in point.service_key)
    self.assertEqual([], point.intro_authentication)

  def _assert_matches_duckduckgo(self, desc):
    self.assertEqual('y3olqqblqw2gbh6phimfuiroechjjafa', desc.descriptor_id)
    self.assertEqual(2, desc.version)
    self.assertEqual(EXPECTED_DDG_PERMANENT_KEY, desc.permanent_key)
    self.assertEqual('e24kgecavwsznj7gpbktqsiwgvngsf4e', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2015, 2, 23, 20, 0, 0), desc.published)
    self.assertEqual([2, 3], desc.protocol_versions)
    self.assertEqual(EXPECTED_DDG_INTRODUCTION_POINTS_ENCODED, desc.introduction_points_encoded)
    self.assertEqual([], desc.introduction_points_auth)
    self.assertEqual(EXPECTED_DDG_INTRODUCTION_POINTS_CONTENT, desc.introduction_points_content)
    self.assertEqual(EXPECTED_DDG_SIGNATURE, desc.signature)

    introduction_points = desc.introduction_points()
    self.assertEqual(3, len(introduction_points))

    point = introduction_points[0]
    self.assertEqual('iwki77xtbvp6qvedfrwdzncxs3ckayeu', point.identifier)
    self.assertEqual('178.62.222.129', point.address)
    self.assertEqual(443, point.port)
    self.assertEqual(EXPECT_POINT_1_ONION_KEY, point.onion_key)
    self.assertEqual(EXPECT_POINT_1_SERVICE_KEY, point.service_key)
    self.assertEqual([], point.intro_authentication)

    point = introduction_points[1]
    self.assertEqual('em4gjk6eiiualhmlyiifrzc7lbtrsbip', point.identifier)
    self.assertEqual('46.4.174.52', point.address)
    self.assertEqual(443, point.port)
    self.assertEqual(EXPECT_POINT_2_ONION_KEY, point.onion_key)
    self.assertEqual(EXPECT_POINT_2_SERVICE_KEY, point.service_key)
    self.assertEqual([], point.intro_authentication)

    point = introduction_points[2]
    self.assertEqual('jqhfl364x3upe6lqnxizolewlfrsw2zy', point.identifier)
    self.assertEqual('62.210.82.169', point.address)
    self.assertEqual(443, point.port)
    self.assertEqual(EXPECT_POINT_3_ONION_KEY, point.onion_key)
    self.assertEqual(EXPECT_POINT_3_SERVICE_KEY, point.service_key)
    self.assertEqual([], point.intro_authentication)

  def test_minimal_hidden_service_descriptor(self):
    """
    Basic sanity check that we can parse a hidden service descriptor with minimal attributes.
    """

    desc = get_hidden_service_descriptor()

    self.assertEqual('y3olqqblqw2gbh6phimfuiroechjjafa', desc.descriptor_id)
    self.assertEqual(2, desc.version)
    self.assertTrue(CRYPTO_BLOB in desc.permanent_key)
    self.assertEqual('e24kgecavwsznj7gpbktqsiwgvngsf4e', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2015, 2, 23, 20, 0, 0), desc.published)
    self.assertEqual([2, 3], desc.protocol_versions)
    self.assertEqual('-----BEGIN MESSAGE-----\n-----END MESSAGE-----', desc.introduction_points_encoded)
    self.assertEqual([], desc.introduction_points_auth)
    self.assertEqual(b'', desc.introduction_points_content)
    self.assertTrue(CRYPTO_BLOB in desc.signature)
    self.assertEqual([], desc.introduction_points())

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    desc = get_hidden_service_descriptor({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], desc.get_unrecognized_lines())

  def test_proceeding_line(self):
    """
    Includes a line prior to the 'rendezvous-service-descriptor' entry.
    """

    desc_text = b'hibernate 1\n' + get_hidden_service_descriptor(content = True)
    self._expect_invalid_attr(desc_text)

  def test_trailing_line(self):
    """
    Includes a line after the 'router-signature' entry.
    """

    desc_text = get_hidden_service_descriptor(content = True) + b'\nhibernate 1'
    self._expect_invalid_attr(desc_text)

  def test_required_fields(self):
    """
    Check that we require the mandatory fields.
    """

    line_to_attr = {
      'rendezvous-service-descriptor': 'descriptor_id',
      'version': 'version',
      'permanent-key': 'permanent_key',
      'secret-id-part': 'secret_id_part',
      'publication-time': 'published',
      'introduction-points': 'introduction_points_encoded',
      'protocol-versions': 'protocol_versions',
      'signature': 'signature',
    }

    for line in REQUIRED_FIELDS:
      desc_text = get_hidden_service_descriptor(content = True, exclude = (line,))

      expected = [] if line == 'protocol-versions' else None
      self._expect_invalid_attr(desc_text, line_to_attr[line], expected)

  def test_invalid_version(self):
    """
    Checks that our version field expects a numeric value.
    """

    test_values = (
      '',
      '-10',
      'hello',
    )

    for test_value in test_values:
      desc_text = get_hidden_service_descriptor({'version': test_value}, content = True)
      self._expect_invalid_attr(desc_text, 'version')

  def test_invalid_protocol_versions(self):
    """
    Checks that our protocol-versions field expects comma separated numeric
    values.
    """

    test_values = (
      '',
      '-10',
      'hello',
      '10,',
      ',10',
      '10,-10',
      '10,hello',
    )

    for test_value in test_values:
      desc_text = get_hidden_service_descriptor({'protocol-versions': test_value}, content = True)
      self._expect_invalid_attr(desc_text, 'protocol_versions', [])

  def test_introduction_points_when_empty(self):
    """
    It's valid to advertise zero introduciton points. I'm not clear if this
    would mean an empty protocol-versions field or that it's omitted but either
    are valid according to the spec.
    """

    missing_field_desc = get_hidden_service_descriptor(exclude = ('introduction-points',))

    self.assertEqual(None, missing_field_desc.introduction_points_encoded)
    self.assertEqual([], missing_field_desc.introduction_points_auth)
    self.assertEqual(None, missing_field_desc.introduction_points_content)
    self.assertEqual([], missing_field_desc.introduction_points())

    empty_field_desc = get_hidden_service_descriptor({'introduction-points': MESSAGE_BLOCK % ''})

    self.assertEqual((MESSAGE_BLOCK % '').strip(), empty_field_desc.introduction_points_encoded)
    self.assertEqual([], empty_field_desc.introduction_points_auth)
    self.assertEqual(b'', empty_field_desc.introduction_points_content)
    self.assertEqual([], empty_field_desc.introduction_points())

  def test_introduction_points_when_not_base64(self):
    """
    Checks the introduction-points field when the content isn't base64 encoded.
    """

    test_values = (
      MESSAGE_BLOCK % '12345',
      MESSAGE_BLOCK % 'hello',
    )

    for test_value in test_values:
      desc_text = get_hidden_service_descriptor({'introduction-points': test_value}, content = True)

      desc = self._expect_invalid_attr(desc_text, 'introduction_points_encoded', test_value.strip())
      self.assertEqual([], desc.introduction_points_auth)
      self.assertEqual(None, desc.introduction_points_content)
      self.assertEqual([], desc.introduction_points())

  def _expect_invalid_attr(self, desc_text, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to desc_text having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """

    self.assertRaises(ValueError, HiddenServiceDescriptor, desc_text, True)
    desc = HiddenServiceDescriptor(desc_text, validate = False)

    if attr:
      # check that the invalid attribute matches the expected value when
      # constructed without validation

      self.assertEqual(expected_value, getattr(desc, attr))
    else:
      # check a default attribute
      self.assertEqual('y3olqqblqw2gbh6phimfuiroechjjafa', desc.descriptor_id)

    return desc
