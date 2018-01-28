"""
Unit tests for the stem.client.cell.
"""

import datetime
import os
import unittest

from stem.client import ZERO, CertType, CloseReason, Address, Certificate
from test.unit.client import test_data

from stem.client.cell import (
  FIXED_PAYLOAD_LEN,
  Cell,
  PaddingCell,
  RelayCell,
  DestroyCell,
  CreateFastCell,
  CreatedFastCell,
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

RELAY_CELLS = {
  '\x00\x01\x03\r\x00\x00\x00\x01!\xa3?\xec' + ZERO * 500: ('RELAY_BEGIN_DIR', 13, 1, 1, '', 564346860),
  '\x00\x01\x03\x02\x00\x00\x00\x01\x15:m\xe0\x00&GET /tor/server/authority HTTP/1.0\r\n\r\n' + ZERO * 460: ('RELAY_DATA', 2, 1, 1, 'GET /tor/server/authority HTTP/1.0\r\n\r\n', 356150752),
}

DESTROY_CELLS = {
  '\x80\x00\x00\x00\x04\x00' + ZERO * 508: (2147483648, CloseReason.NONE, 0),
  '\x80\x00\x00\x00\x04\x03' + ZERO * 508: (2147483648, CloseReason.REQUESTED, 3),
}

CREATE_FAST_CELLS = {
  ('\x80\x00\x00\x00\x05\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce' + ZERO * 489): (2147483648, '\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce'),
}

CREATED_FAST_CELLS = {
  ('\x80\x00\x00\x00\x06\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\xb2' + ZERO * 469): (2147483648, '\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce', '\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\xb2'),
}

VERSIONS_CELLS = {
  '\x00\x00\x07\x00\x00': [],
  '\x00\x00\x07\x00\x02\x00\x01': [1],
  '\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03': [1, 2, 3],
}

NETINFO_CELLS = {
  '\x00\x00\x08ZZ\xb6\x90\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02' + ZERO * (FIXED_PAYLOAD_LEN - 17): (datetime.datetime(2018, 1, 14, 1, 46, 56), Address('127.0.0.1'), [Address('97.113.15.2')]),
}

VPADDING_CELLS = {
  '\x00\x00\x80\x00\x00': '',
  '\x00\x00\x80\x00\x01\x08': '\x08',
  '\x00\x00\x80\x00\x02\x08\x11': '\x08\x11',
  '\x00\x00\x80\x01\xfd' + RANDOM_PAYLOAD: RANDOM_PAYLOAD,
}

CERTS_CELLS = {
  '\x00\x00\x81\x00\x01\x00': [],
  '\x00\x00\x81\x00\x04\x01\x01\x00\x00': [Certificate(1, '')],
  '\x00\x00\x81\x00\x05\x01\x01\x00\x01\x08': [Certificate(1, '\x08')],
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
    self.assertRaisesRegexp(NotImplementedError, 'Unpacking not yet implemented for AUTHORIZE cells', Cell.pop, '\x00\x00\x84\x00\x06\x00\x01\x00\x02\x00\x03', 2)

  def test_unpack_for_new_link(self):
    expected_certs = (
      (CertType.LINK, 1, '0\x82\x02F0\x82\x01\xaf'),
      (CertType.IDENTITY, 2, '0\x82\x01\xc90\x82\x012'),
      (CertType.UNKNOWN, 4, '\x01\x04\x00\x06m\x1f'),
      (CertType.UNKNOWN, 5, '\x01\x05\x00\x06m\n\x01'),
      (CertType.UNKNOWN, 7, '\x1a\xa5\xb3\xbd\x88\xb1C'),
    )

    content = test_data('new_link_cells')

    version_cell, content = Cell.pop(content, 2)
    self.assertEqual(VersionsCell([3, 4, 5]), version_cell)

    certs_cell, content = Cell.pop(content, 2)
    self.assertEqual(CertsCell, type(certs_cell))
    self.assertEqual(len(expected_certs), len(certs_cell.certificates))

    for i, (cert_type, cert_type_int, cert_prefix) in enumerate(expected_certs):
      self.assertEqual(cert_type, certs_cell.certificates[i].type)
      self.assertEqual(cert_type_int, certs_cell.certificates[i].type_int)
      self.assertTrue(certs_cell.certificates[i].value.startswith(cert_prefix))

    auth_challenge_cell, content = Cell.pop(content, 2)
    self.assertEqual(AuthChallengeCell([1, 3], '\x89Y\t\x99\xb2\x1e\xd9*V\xb6\x1bn\n\x05\xd8/\xe3QH\x85\x13Z\x17\xfc\x1c\x00{\xa9\xae\x83^K'), auth_challenge_cell)

    netinfo_cell, content = Cell.pop(content, 2)
    self.assertEqual(NetinfoCell, type(netinfo_cell))
    self.assertEqual(datetime.datetime(2018, 1, 14, 1, 46, 56), netinfo_cell.timestamp)
    self.assertEqual(Address('127.0.0.1'), netinfo_cell.receiver_address)
    self.assertEqual([Address('97.113.15.2')], netinfo_cell.sender_addresses)

    self.assertEqual('', content)  # check that we've consumed all of the bytes

  def test_padding_cell(self):
    for cell_bytes, payload in PADDING_CELLS.items():
      self.assertEqual(cell_bytes, PaddingCell(payload).pack(2))
      self.assertEqual(payload, Cell.pop(cell_bytes, 2)[0].payload)

  def test_relay_cell(self):
    for cell_bytes, (command, command_int, circ_id, stream_id, data, digest) in RELAY_CELLS.items():
      self.assertEqual(cell_bytes, RelayCell(circ_id, command, data, digest, stream_id).pack(2))
      self.assertEqual(cell_bytes, RelayCell(circ_id, command_int, data, digest, stream_id).pack(2))

      cell = Cell.pop(cell_bytes, 2)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(command, cell.command)
      self.assertEqual(command_int, cell.command_int)
      self.assertEqual(data, cell.data)
      self.assertEqual(digest, cell.digest)
      self.assertEqual(stream_id, cell.stream_id)

  def test_destroy_cell(self):
    for cell_bytes, (circ_id, reason, reason_int) in DESTROY_CELLS.items():
      self.assertEqual(cell_bytes, DestroyCell(circ_id, reason).pack(5))
      self.assertEqual(cell_bytes, DestroyCell(circ_id, reason_int).pack(5))

      cell = Cell.pop(cell_bytes, 5)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(reason, cell.reason)
      self.assertEqual(reason_int, cell.reason_int)

    self.assertRaisesRegexp(ValueError, 'Circuit closure reason should be a single byte, but was 2', Cell.pop, '\x80\x00\x00\x00\x04\x01\x01' + ZERO * 507, 5)

  def test_create_fast_cell(self):
    for cell_bytes, (circ_id, key_material) in CREATE_FAST_CELLS.items():
      self.assertEqual(cell_bytes, CreateFastCell(circ_id, key_material).pack(5))

      cell = Cell.pop(cell_bytes, 5)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(key_material, cell.key_material)

    self.assertRaisesRegexp(ValueError, 'Key material should be 20 bytes, but was 3', CreateFastCell, 5, 'boo')

  def test_created_fast_cell(self):
    for cell_bytes, (circ_id, key_material, derivative_key) in CREATED_FAST_CELLS.items():
      self.assertEqual(cell_bytes, CreatedFastCell(circ_id, derivative_key, key_material).pack(5))

      cell = Cell.pop(cell_bytes, 5)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(key_material, cell.key_material)
      self.assertEqual(derivative_key, cell.derivative_key)

    self.assertRaisesRegexp(ValueError, 'Key material should be 20 bytes, but was 3', CreateFastCell, 5, 'boo')

  def test_versions_cell(self):
    for cell_bytes, versions in VERSIONS_CELLS.items():
      self.assertEqual(cell_bytes, VersionsCell(versions).pack())
      self.assertEqual(versions, Cell.pop(cell_bytes, 2)[0].versions)

  def test_netinfo_cell(self):
    for cell_bytes, (timestamp, receiver_address, sender_addresses) in NETINFO_CELLS.items():
      self.assertEqual(cell_bytes, NetinfoCell(receiver_address, sender_addresses, timestamp).pack(2))

      cell = Cell.pop(cell_bytes, 2)[0]
      self.assertEqual(timestamp, cell.timestamp)
      self.assertEqual(receiver_address, cell.receiver_address)
      self.assertEqual(sender_addresses, cell.sender_addresses)

  def test_vpadding_cell(self):
    for cell_bytes, payload in VPADDING_CELLS.items():
      self.assertEqual(cell_bytes, VPaddingCell(payload = payload).pack(2))
      self.assertEqual(payload, Cell.pop(cell_bytes, 2)[0].payload)

    self.assertRaisesRegexp(ValueError, 'VPaddingCell constructor specified both a size of 5 bytes and payload of 1 bytes', VPaddingCell, 5, '\x02')

  def test_certs_cell(self):
    for cell_bytes, certs in CERTS_CELLS.items():
      self.assertEqual(cell_bytes, CertsCell(certs).pack(2))
      self.assertEqual(certs, Cell.pop(cell_bytes, 2)[0].certificates)

    # extra bytes after the last certificate should be ignored

    self.assertEqual([Certificate(1, '\x08')], Cell.pop('\x00\x00\x81\x00\x07\x01\x01\x00\x01\x08\x06\x04', 2)[0].certificates)

    # ... but truncated or missing certificates should error

    self.assertRaisesRegexp(ValueError, 'CERTS cell should have a certificate with 3 bytes, but only had 1 remaining', Cell.pop, '\x00\x00\x81\x00\x05\x01\x01\x00\x03\x08', 2)
    self.assertRaisesRegexp(ValueError, 'CERTS cell indicates it should have 2 certificates, but only contained 1', Cell.pop, '\x00\x00\x81\x00\x05\x02\x01\x00\x01\x08', 2)

  def test_auth_challenge_cell(self):
    for cell_bytes, (challenge, methods) in AUTH_CHALLENGE_CELLS.items():
      self.assertEqual(cell_bytes, AuthChallengeCell(methods, challenge).pack(2))

      cell = Cell.pop(cell_bytes, 2)[0]
      self.assertEqual(challenge, cell.challenge)
      self.assertEqual(methods, cell.methods)

    self.assertRaisesRegexp(ValueError, 'AUTH_CHALLENGE cell should have a payload of 38 bytes, but only had 16', Cell.pop, '\x00\x00\x82\x00&%s\x00\x02\x00\x01\x00\x03' % CHALLENGE[:10], 2)
    self.assertRaisesRegexp(ValueError, 'AUTH_CHALLENGE should have 3 methods, but only had 4 bytes for it', Cell.pop, '\x00\x00\x82\x00&%s\x00\x03\x00\x01\x00\x03' % CHALLENGE, 2)
