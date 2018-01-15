"""
Unit tests for the stem.client.cell.
"""

import datetime
import os
import unittest

from stem.client import ZERO, Address, Certificate
from test.unit.client import test_data

from stem.client.cell import (
  FIXED_PAYLOAD_LEN,
  Cell,
  PaddingCell,
  VersionsCell,
  NetinfoCell,
  VPaddingCell,
  CertsCell,
  AuthChallengeCell,
)

RANDOM_PAYLOAD = os.urandom(FIXED_PAYLOAD_LEN)
CHALLENGE = '\x89Y\t\x99\xb2\x1e\xd9*V\xb6\x1bn\n\x05\xd8/\xe3QH\x85\x13Z\x17\xfc\x1c\x00{\xa9\xae\x83^K'

PADDING_CELLS = {
  '\x00\x00\x00' + RANDOM_PAYLOAD: RANDOM_PAYLOAD,
}

VERSIONS_CELLS = {
  '\x00\x00\x07\x00\x00': [],
  '\x00\x00\x07\x00\x02\x00\x01': [1],
  '\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03': [1, 2, 3],
}

NETINFO_CELL = '\x00\x00\x08ZZ\xb6\x90\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02' + ZERO * (FIXED_PAYLOAD_LEN - 17)

VPADDING_CELLS = {
  '\x00\x00\x80\x00\x00': '',
  '\x00\x00\x80\x00\x01\x08': '\x08',
  '\x00\x00\x80\x00\x02\x08\x11': '\x08\x11',
  '\x00\x00\x80\x01\xfd' + RANDOM_PAYLOAD: RANDOM_PAYLOAD,
}

CERTS_CELLS = {
  '\x00\x00\x81\x00\x01\x00': [],
  '\x00\x00\x81\x00\x04\x01\x01\x00\x00': [Certificate(type = 1, value = '')],
  '\x00\x00\x81\x00\x05\x01\x01\x00\x01\x08': [Certificate(type = 1, value = '\x08')],
}

AUTH_CHALLENGE_CELLS = {
  '\x00\x00\x82\x00&%s\x00\x02\x00\x01\x00\x03' % CHALLENGE: (CHALLENGE, [1, 3]),
}


class TestCell(unittest.TestCase):
  def test_by_name(self):
    cls = Cell.by_name('NETINFO')
    self.assertEqual('NETINFO', cls.NAME)
    self.assertEqual(8, cls.VALUE)
    self.assertEqual(True, cls.IS_FIXED_SIZE)

    self.assertRaises(ValueError, Cell.by_name, 'NOPE')
    self.assertRaises(ValueError, Cell.by_name, 85)
    self.assertRaises(ValueError, Cell.by_name, None)

  def test_by_value(self):
    cls = Cell.by_value(8)
    self.assertEqual('NETINFO', cls.NAME)
    self.assertEqual(8, cls.VALUE)
    self.assertEqual(True, cls.IS_FIXED_SIZE)

    self.assertRaises(ValueError, Cell.by_value, 'NOPE')
    self.assertRaises(ValueError, Cell.by_value, 85)
    self.assertRaises(ValueError, Cell.by_value, None)

  def test_unpack_not_implemented(self):
    self.assertRaisesRegexp(NotImplementedError, 'Unpacking not yet implemented for AUTHORIZE cells', Cell.unpack, '\x00\x00\x84\x00\x06\x00\x01\x00\x02\x00\x03', 2)

  def test_unpack_for_new_link(self):
    expected_certs = (
      (1, '0\x82\x02F0\x82\x01\xaf'),
      (2, '0\x82\x01\xc90\x82\x012'),
      (4, '\x01\x04\x00\x06m\x1f'),
      (5, '\x01\x05\x00\x06m\n\x01'),
      (7, '\x1a\xa5\xb3\xbd\x88\xb1C'),
    )

    link_cells = Cell.unpack(test_data('new_link_cells'), 2)
    self.assertEqual(4, len(link_cells))
    self.assertEqual(VersionsCell([3, 4, 5]), link_cells[0])

    certs_cell = link_cells[1]
    self.assertEqual(CertsCell, type(certs_cell))
    self.assertEqual(len(expected_certs), len(certs_cell.certificates))

    for i, (cert_type, cert_prefix) in enumerate(expected_certs):
      self.assertEqual(cert_type, certs_cell.certificates[i].type)
      self.assertTrue(certs_cell.certificates[i].value.startswith(cert_prefix))

    self.assertEqual(AuthChallengeCell('\x89Y\t\x99\xb2\x1e\xd9*V\xb6\x1bn\n\x05\xd8/\xe3QH\x85\x13Z\x17\xfc\x1c\x00{\xa9\xae\x83^K', [1, 3]), link_cells[2])

    netinfo_cell = link_cells[3]
    self.assertEqual(NetinfoCell, type(netinfo_cell))
    self.assertEqual(datetime.datetime(2018, 1, 14, 1, 46, 56), netinfo_cell.timestamp)
    self.assertEqual(Address(type='IPv4', type_int=4, value='127.0.0.1', value_bin='\x7f\x00\x00\x01'), netinfo_cell.receiver_address)
    self.assertEqual([Address(type='IPv4', type_int=4, value='97.113.15.2', value_bin='aq\x0f\x02')], netinfo_cell.sender_addresses)

  def test_padding_packing(self):
    for cell_bytes, payload in PADDING_CELLS.items():
      self.assertEqual(cell_bytes, PaddingCell.pack(2, payload))
      self.assertEqual(payload, Cell.unpack(cell_bytes, 2)[0].payload)

  def test_versions_packing(self):
    for cell_bytes, versions in VERSIONS_CELLS.items():
      self.assertEqual(cell_bytes, VersionsCell.pack(versions))
      self.assertEqual(versions, Cell.unpack(cell_bytes, 2)[0].versions)

  def test_netinfo_packing(self):
    cell = Cell.unpack(NETINFO_CELL, 2)[0]

    self.assertEqual(datetime.datetime(2018, 1, 14, 1, 46, 56), cell.timestamp)
    self.assertEqual(Address(type='IPv4', type_int=4, value='127.0.0.1', value_bin='\x7f\x00\x00\x01'), cell.receiver_address)
    self.assertEqual([Address(type='IPv4', type_int=4, value='97.113.15.2', value_bin='aq\x0f\x02')], cell.sender_addresses)

  def test_vpadding_packing(self):
    for cell_bytes, payload in VPADDING_CELLS.items():
      self.assertEqual(cell_bytes, VPaddingCell.pack(2, payload = payload))
      self.assertEqual(payload, Cell.unpack(cell_bytes, 2)[0].payload)

    self.assertRaisesRegexp(ValueError, 'VPaddingCell.pack caller specified both a size of 5 bytes and payload of 1 bytes', VPaddingCell.pack, 2, 5, '\x02')

  def test_certs_packing(self):
    for cell_bytes, certs in CERTS_CELLS.items():
      self.assertEqual(cell_bytes, CertsCell.pack(2, certs))
      self.assertEqual(certs, Cell.unpack(cell_bytes, 2)[0].certificates)

    # extra bytes after the last certificate should be ignored

    self.assertEqual([Certificate(type = 1, value = '\x08')], Cell.unpack('\x00\x00\x81\x00\x07\x01\x01\x00\x01\x08\x06\x04', 2)[0].certificates)

    # ... but truncated or missing certificates should error

    self.assertRaisesRegexp(ValueError, 'CERTS cell should have a certificate with 3 bytes, but only had 1 remaining', Cell.unpack, '\x00\x00\x81\x00\x05\x01\x01\x00\x03\x08', 2)
    self.assertRaisesRegexp(ValueError, 'CERTS cell indicates it should have 2 certificates, but only contained 1', Cell.unpack, '\x00\x00\x81\x00\x05\x02\x01\x00\x01\x08', 2)

  def test_auth_challenge_packing(self):
    for cell_bytes, (challenge, methods) in AUTH_CHALLENGE_CELLS.items():
      self.assertEqual(cell_bytes, AuthChallengeCell.pack(2, methods, challenge))

      cell = Cell.unpack(cell_bytes, 2)[0]
      self.assertEqual(challenge, cell.challenge)
      self.assertEqual(methods, cell.methods)

    self.assertRaisesRegexp(ValueError, 'AUTH_CHALLENGE cell should have a payload of 38 bytes, but only had 16', Cell.unpack, '\x00\x00\x82\x00&%s\x00\x02\x00\x01\x00\x03' % CHALLENGE[:10], 2)
    self.assertRaisesRegexp(ValueError, 'AUTH_CHALLENGE should have 3 methods, but only had 4 bytes for it', Cell.unpack, '\x00\x00\x82\x00&%s\x00\x03\x00\x01\x00\x03' % CHALLENGE, 2)
