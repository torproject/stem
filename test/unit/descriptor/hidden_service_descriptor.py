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

EXPECTED_DDG_INTRODUCTION_POINTS_BLOB = """\
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

EXPECTED_DDG_SIGNATURE = """\
-----BEGIN SIGNATURE-----
VKMmsDIUUFOrpqvcQroIZjDZTKxqNs88a4M9Te8cR/ZvS7H2nffv6iQs0tom5X4D
4Dy4iZiy+pwYxdHfaOxmdpgMCRvgPb34MExWr5YemH0QuGtnlp5Wxr8GYaAQVuZX
cZjQLW0juUYCbgIGdxVEBnlEt2rgBSM9+1oR7EAfV1U=
-----END SIGNATURE-----\
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
    self.assertEqual('2', desc.version)
    self.assertEqual('6355jaerje3bqozopwq2qmpf4iviizdn', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2014, 10, 31, 23, 0, 0), desc.published)
    self.assertEqual(['2', '3'], desc.protocol_versions)

  def _assert_matches_duckduckgo(self, desc):
    self.assertEqual('y3olqqblqw2gbh6phimfuiroechjjafa', desc.descriptor_id)
    self.assertEqual('2', desc.version)
    self.assertEqual(EXPECTED_DDG_PERMANENT_KEY, desc.permanent_key)
    self.assertEqual('e24kgecavwsznj7gpbktqsiwgvngsf4e', desc.secret_id_part)
    self.assertEqual(datetime.datetime(2015, 2, 23, 20, 0, 0), desc.published)
    self.assertEqual(['2', '3'], desc.protocol_versions)
    self.assertEqual(EXPECTED_DDG_INTRODUCTION_POINTS_BLOB, desc.introduction_points_blob)
    self.assertEqual(EXPECTED_DDG_SIGNATURE, desc.signature)
