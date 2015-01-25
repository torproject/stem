"""
Unit tests for stem.descriptor.tordnsel.
"""

import io
import unittest
import datetime

from stem.util.tor_tools import is_valid_fingerprint
from stem.descriptor.tordnsel import TorDNSEL, _parse_file

TEST_DESC = b"""\
@type tordnsel 1.0
Downloaded 2013-08-19 04:02:03
ExitNode 003A71137D959748C8157C4A76ECA639CEF5E33E
Published 2013-08-19 02:13:53
LastStatus 2013-08-19 03:02:47
ExitAddress 66.223.170.168 2013-08-19 03:18:51
ExitNode 00FF300624FECA7F40515C8D854EE925332580D6
Published 2013-08-18 07:02:14
LastStatus 2013-08-18 09:02:58
ExitAddress 82.252.181.153 2013-08-18 08:03:01
ExitAddress 82.252.181.154 2013-08-18 08:03:02
ExitAddress 82.252.181.155 2013-08-18 08:03:03
ExitNode 030B22437D99B2DB2908B747B6962EAD13AB4039
Published 2013-08-18 12:44:20
LastStatus 2013-08-18 13:02:57
ExitAddress 46.10.211.205 2013-08-18 13:18:48
"""

MALFORMED_ENTRY_1 = b"""\
ExitNode 030B22437D99B2DB2908B747B6962EAD13AB4038
Published Today!
LastStatus 2013-08-18 13:02:57
ExitAddress 46.10.211.205 2013-08-18 13:18:48
"""

MALFORMED_ENTRY_2 = b"""\
@type tordnsel 1.0
ExitNode 030B22437D99B2DB2908B747B6962EAD13AB4038
Published Today!
LastStatus 2013-08-18 13:02:57
ExitAddress 46.10.211.205 2013-08-18 Never
"""


class TestTorDNSELDescriptor(unittest.TestCase):
  def test_parse_file(self):
    """
    Try parsing a document via the _parse_file() function.
    """

    # parse file and assert values

    descriptors = list(_parse_file(io.BytesIO(TEST_DESC)))
    self.assertEqual(3, len(descriptors))
    self.assertTrue(isinstance(descriptors[0], TorDNSEL))
    desc = descriptors[1]
    self.assertTrue(is_valid_fingerprint(desc.fingerprint))
    self.assertEqual('00FF300624FECA7F40515C8D854EE925332580D6', desc.fingerprint)
    self.assertEqual(datetime.datetime(2013, 8, 18, 7, 2, 14), desc.published)
    self.assertEqual(datetime.datetime(2013, 8, 18, 9, 2, 58), desc.last_status)
    self.assertEqual(3, len(desc.exit_addresses))
    exit = desc.exit_addresses[0]
    self.assertEqual('82.252.181.153', exit[0])
    self.assertEqual(datetime.datetime(2013, 8, 18, 8, 3, 1), exit[1])

    # block content raises value error

    extra = b'ExtraContent goes here\n'
    descriptors = _parse_file(io.BytesIO(TEST_DESC + extra), validate = True)
    self.assertRaises(ValueError, list, descriptors)

    # malformed fingerprint raises value errors

    extra = b'ExitNode 030B22437D99B2DB2908B747B6'
    self.assertRaises(ValueError, list, _parse_file(io.BytesIO(TEST_DESC + extra), validate = True))

    # malformed date raises value errors

    self.assertRaises(ValueError, list, _parse_file(io.BytesIO(TEST_DESC + MALFORMED_ENTRY_1), validate = True))

    # skip exit address if malformed date and validate is False

    desc = next(_parse_file(io.BytesIO(MALFORMED_ENTRY_2), validate=False))
    self.assertTrue(is_valid_fingerprint(desc.fingerprint))
    self.assertEqual('030B22437D99B2DB2908B747B6962EAD13AB4038', desc.fingerprint)
    self.assertEqual(0, len(desc.exit_addresses))
