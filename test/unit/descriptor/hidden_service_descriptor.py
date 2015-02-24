"""
Unit tests for stem.descriptor.hidden_service_descriptor.
"""

import datetime
import unittest

import stem.descriptor

from test.unit.descriptor import get_resource

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

EXPECTED_DDG_INTRODUCTION_POINTS_CONTENT = """\
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
