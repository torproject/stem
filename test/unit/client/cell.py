"""
Unit tests for the stem.client.cell.
"""

import datetime
import hashlib
import os
import unittest

from stem.client.datatype import ZERO, CertType, CloseReason, Address, Certificate
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
CHALLENGE = b'\x89Y\t\x99\xb2\x1e\xd9*V\xb6\x1bn\n\x05\xd8/\xe3QH\x85\x13Z\x17\xfc\x1c\x00{\xa9\xae\x83^K'

PADDING_CELLS = {
  b'\x00\x00\x00' + RANDOM_PAYLOAD: (RANDOM_PAYLOAD, 2),
}

RELAY_CELLS = {
  b'\x00\x01\x03\r\x00\x00\x00\x01!\xa3?\xec\x00\x00' + ZERO * 498: ('RELAY_BEGIN_DIR', 13, 1, 1, b'', 564346860, ZERO * 498, 2),
  b'\x00\x01\x03\x02\x00\x00\x00\x01\x15:m\xe0\x00&GET /tor/server/authority HTTP/1.0\r\n\r\n' + ZERO * 460: ('RELAY_DATA', 2, 1, 1, b'GET /tor/server/authority HTTP/1.0\r\n\r\n', 356150752, ZERO * 460, 2),
  b'\x00\x01\x03\x02\x00\x00\x00\x01\x15:m\xe0\x00&GET /tor/server/authority HTTP/1.0\r\n\r\n' + b'\x01' + ZERO * 459: ('RELAY_DATA', 2, 1, 1, b'GET /tor/server/authority HTTP/1.0\r\n\r\n', 356150752, b'\x01' + ZERO * 459, 2),
}

DESTROY_CELLS = {
  b'\x80\x00\x00\x00\x04\x00' + ZERO * 508: (2147483648, CloseReason.NONE, 0, ZERO * 508, 5),
  b'\x80\x00\x00\x00\x04\x03' + ZERO * 508: (2147483648, CloseReason.REQUESTED, 3, ZERO * 508, 5),
  b'\x80\x00\x00\x00\x04\x01' + b'\x01' + ZERO * 507: (2147483648, CloseReason.PROTOCOL, 1, b'\x01' + ZERO * 507, 5),
}

CREATE_FAST_CELLS = {
  (b'\x80\x00\x00\x00\x05\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce' + ZERO * 489): (2147483648, b'\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce', ZERO * 489, 5),
  (b'\x80\x00\x00\x00\x05\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\x00' + ZERO * 489): (2147483648, b'\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\x00', ZERO * 489, 5),
  (b'\x80\x00\x00\x00\x05\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\x00' + b'\x01' + ZERO * 488): (2147483648, b'\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\x00', b'\x01' + ZERO * 488, 5),
}

CREATED_FAST_CELLS = {
  (b'\x80\x00\x00\x00\x06\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\xb2' + ZERO * 469): (2147483648, b'\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce', b'\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\xb2', ZERO * 469, 5),
  (b'\x80\x00\x00\x00\x06\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\x00' + ZERO * 469): (2147483648, b'\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce', b'\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\x00', ZERO * 469, 5),
  (b'\x80\x00\x00\x00\x06\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\x00' + b'\x01' + ZERO * 468): (2147483648, b'\x92O\x0c\xcb\xa8\xac\xfb\xc9\x7f\xd0\rz\x1a\x03u\x91\xceas\xce', b'\x13Z\x99\xb2\x1e\xb6\x05\x85\x17\xfc\x1c\x00{\xa9\xae\x83^K\x99\x00', b'\x01' + ZERO * 468, 5),
}

VERSIONS_CELLS = {
  b'\x00\x00\x07\x00\x00': ([], 2),
  b'\x00\x00\x07\x00\x02\x00\x01': ([1], 2),
  b'\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03': ([1, 2, 3], 2),
  b'\x00\x00\x00\x00\x07\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04': ([1, 2, 3, 4], 4),
}

NETINFO_CELLS = {
  b'\x00\x00\x08ZZ\xb6\x90\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02' + ZERO * (FIXED_PAYLOAD_LEN - 17): (datetime.datetime(2018, 1, 14, 1, 46, 56), Address('127.0.0.1'), [Address('97.113.15.2')], ZERO * 492, 2),
  b'\x00\x00\x08ZZ\xb6\x90\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02' + b'\x01' + ZERO * (FIXED_PAYLOAD_LEN - 18): (datetime.datetime(2018, 1, 14, 1, 46, 56), Address('127.0.0.1'), [Address('97.113.15.2')], b'\x01' + ZERO * 491, 2),
}

VPADDING_CELL_EMPTY_PACKED = b'\x00\x00\x80\x00\x00'

VPADDING_CELLS = {
  VPADDING_CELL_EMPTY_PACKED: (b'', 2),
  b'\x00\x00\x80\x00\x01\x08': (b'\x08', 2),
  b'\x00\x00\x80\x00\x02\x08\x11': (b'\x08\x11', 2),
  b'\x00\x00\x80\x01\xfd' + RANDOM_PAYLOAD: (RANDOM_PAYLOAD, 2),
}

CERTS_CELLS = {
  b'\x00\x00\x81\x00\x01\x00': ([], b'', 2),
  b'\x00\x00\x81\x00\x04\x01\x01\x00\x00': ([Certificate(1, b'')], b'', 2),
  b'\x00\x00\x81\x00\x05\x01\x01\x00\x01\x08': ([Certificate(1, b'\x08')], b'', 2),
  b'\x00\x00\x81\x00\x07\x01\x01\x00\x01\x08' + b'\x06\x04': ([Certificate(1, b'\x08')], b'\x06\x04', 2),
}

AUTH_CHALLENGE_CELLS = {
  b'\x00\x00\x82\x00\x26' + CHALLENGE + b'\x00\x02\x00\x01\x00\x03': (CHALLENGE, [1, 3], b'', 2),
  b'\x00\x00\x82\x00\x28' + CHALLENGE + b'\x00\x02\x00\x01\x00\x03' + b'\x01\x02': (CHALLENGE, [1, 3], b'\x01\x02', 2),
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

  def test_unimplemented_cell_methods(self):
    cell_instance = Cell()

    self.assertRaisesWith(NotImplementedError, 'Packing not yet implemented for UNKNOWN cells', cell_instance.pack, 2)
    self.assertRaisesWith(NotImplementedError, 'Unpacking not yet implemented for UNKNOWN cells', cell_instance._unpack, b'dummy', 0, 2)

  def test_payload_too_large(self):
    class OversizedCell(Cell):
      NAME = 'OVERSIZED'
      VALUE = 127  # currently nonsense, but potentially will be allocated in the distant future
      IS_FIXED_SIZE = True

      def pack(self, link_protocol):
        return OversizedCell._pack(link_protocol, ZERO * (FIXED_PAYLOAD_LEN + 1))

    instance = OversizedCell()

    expected_message = 'Cell of type OVERSIZED is too large (%i bytes), must not be more than %i. Check payload size (was %i bytes)' % (FIXED_PAYLOAD_LEN + 4, FIXED_PAYLOAD_LEN + 3, FIXED_PAYLOAD_LEN + 1)
    self.assertRaisesWith(ValueError, expected_message, instance.pack, 2)

  def test_circuit_id_validation(self):
    # only CircuitCell subclasses should provide a circ_id

    self.assertRaisesWith(ValueError, 'PADDING cells should not specify a circuit identifier', PaddingCell._pack, 5, b'', circ_id = 12)

    # CircuitCell should validate its circ_id

    self.assertRaisesWith(ValueError, 'RELAY cells require a circuit identifier', RelayCell._pack, 5, b'', circ_id = None)

    for circ_id in (0, -1, -50):
      expected_msg = 'Circuit identifiers must a positive integer, not %s' % circ_id
      self.assertRaisesWith(ValueError, expected_msg, RelayCell._pack, 5, b'', circ_id = circ_id)

  def test_unpack_for_new_link(self):
    expected_certs = (
      (CertType.LINK, 1, b'0\x82\x02F0\x82\x01\xaf'),
      (CertType.IDENTITY, 2, b'0\x82\x01\xc90\x82\x012'),
      (CertType.ED25519_SIGNING, 4, b'\x01\x04\x00\x06m\x1f'),
      (CertType.LINK_CERT, 5, b'\x01\x05\x00\x06m\n\x01'),
      (CertType.ED25519_IDENTITY, 7, b'\x1a\xa5\xb3\xbd\x88\xb1C'),
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
    self.assertEqual(AuthChallengeCell([1, 3], b'\x89Y\t\x99\xb2\x1e\xd9*V\xb6\x1bn\n\x05\xd8/\xe3QH\x85\x13Z\x17\xfc\x1c\x00{\xa9\xae\x83^K'), auth_challenge_cell)

    netinfo_cell, content = Cell.pop(content, 2)
    self.assertEqual(NetinfoCell, type(netinfo_cell))
    self.assertEqual(datetime.datetime(2018, 1, 14, 1, 46, 56), netinfo_cell.timestamp)
    self.assertEqual(Address('127.0.0.1'), netinfo_cell.receiver_address)
    self.assertEqual([Address('97.113.15.2')], netinfo_cell.sender_addresses)
    self.assertEqual(ZERO * 492, netinfo_cell.unused)

    self.assertEqual(b'', content)  # check that we've consumed all of the bytes

  def test_padding_cell(self):
    for cell_bytes, (payload, link_protocol) in PADDING_CELLS.items():
      self.assertEqual(cell_bytes, PaddingCell(payload).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(payload, cell.payload)
      self.assertEqual(b'', cell.unused)  # always empty
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

  def test_relay_cell(self):
    for cell_bytes, (command, command_int, circ_id, stream_id, data, digest, unused, link_protocol) in RELAY_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, RelayCell(circ_id, command, data, digest, stream_id).pack(link_protocol))
        self.assertEqual(cell_bytes, RelayCell(circ_id, command_int, data, digest, stream_id).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, RelayCell(circ_id, command, data, digest, stream_id, unused = unused).pack(link_protocol))
        self.assertEqual(cell_bytes, RelayCell(circ_id, command_int, data, digest, stream_id, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(command, cell.command)
      self.assertEqual(command_int, cell.command_int)
      self.assertEqual(data, cell.data)
      self.assertEqual(digest, cell.digest)
      self.assertEqual(stream_id, cell.stream_id)
      self.assertEqual(unused, cell.unused)

      self.assertEqual(cell_bytes, cell.pack(link_protocol))

    digest = hashlib.sha1(b'hi')
    self.assertEqual(3257622417, RelayCell(5, 'RELAY_BEGIN_DIR', '', digest, 564346860).digest)
    self.assertEqual(3257622417, RelayCell(5, 'RELAY_BEGIN_DIR', '', digest.digest(), 564346860).digest)
    self.assertEqual(3257622417, RelayCell(5, 'RELAY_BEGIN_DIR', '', 3257622417, 564346860).digest)
    self.assertRaisesWith(ValueError, 'RELAY cell digest must be a hash, string, or int but was a list', RelayCell, 5, 'RELAY_BEGIN_DIR', '', [], 564346860)
    self.assertRaisesRegexp(ValueError, "Invalid enumeration 'NO_SUCH_COMMAND', options are RELAY_BEGIN, RELAY_DATA", RelayCell, 5, 'NO_SUCH_COMMAND', '', 5, 564346860)

    mismatched_data_length_bytes = b''.join((
      b'\x00\x01',  # circ ID
      b'\x03',  # command
      b'\x02',  # relay command
      b'\x00\x00',  # 'recognized'
      b'\x00\x01',  # stream ID
      b'\x15:m\xe0',  # digest
      b'\xFF\xFF',  # data len (65535, clearly invalid)
      ZERO * 498,  # data
    ))

    self.assertRaisesWith(ValueError, 'RELAY cell said it had 65535 bytes of data, but only had 498', Cell.pop, mismatched_data_length_bytes, 2)

  def test_destroy_cell(self):
    for cell_bytes, (circ_id, reason, reason_int, unused, link_protocol) in DESTROY_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, DestroyCell(circ_id, reason).pack(link_protocol))
        self.assertEqual(cell_bytes, DestroyCell(circ_id, reason_int).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, DestroyCell(circ_id, reason, unused = unused).pack(link_protocol))
        self.assertEqual(cell_bytes, DestroyCell(circ_id, reason_int, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(reason, cell.reason)
      self.assertEqual(reason_int, cell.reason_int)
      self.assertEqual(unused, cell.unused)
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

  def test_create_fast_cell(self):
    for cell_bytes, (circ_id, key_material, unused, link_protocol) in CREATE_FAST_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, CreateFastCell(circ_id, key_material).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, CreateFastCell(circ_id, key_material, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(key_material, cell.key_material)
      self.assertEqual(unused, cell.unused)
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

    self.assertRaisesWith(ValueError, 'Key material should be 20 bytes, but was 3', CreateFastCell, 5, 'boo')

  def test_created_fast_cell(self):
    for cell_bytes, (circ_id, key_material, derivative_key, unused, link_protocol) in CREATED_FAST_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, CreatedFastCell(circ_id, derivative_key, key_material).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, CreatedFastCell(circ_id, derivative_key, key_material, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(circ_id, cell.circ_id)
      self.assertEqual(key_material, cell.key_material)
      self.assertEqual(derivative_key, cell.derivative_key)
      self.assertEqual(unused, cell.unused)
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

    self.assertRaisesWith(ValueError, 'Key material should be 20 bytes, but was 3', CreateFastCell, 5, 'boo')

  def test_versions_cell(self):
    for cell_bytes, (versions, link_protocol) in VERSIONS_CELLS.items():
      self.assertEqual(cell_bytes, VersionsCell(versions).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(versions, cell.versions)
      self.assertEqual(b'', cell.unused)  # always empty
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

  def test_netinfo_cell(self):
    for cell_bytes, (timestamp, receiver_address, sender_addresses, unused, link_protocol) in NETINFO_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, NetinfoCell(receiver_address, sender_addresses, timestamp).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, NetinfoCell(receiver_address, sender_addresses, timestamp, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(timestamp, cell.timestamp)
      self.assertEqual(receiver_address, cell.receiver_address)
      self.assertEqual(sender_addresses, cell.sender_addresses)
      self.assertEqual(unused, cell.unused)
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

  def test_vpadding_cell(self):
    for cell_bytes, (payload, link_protocol) in VPADDING_CELLS.items():
      self.assertEqual(cell_bytes, VPaddingCell(payload = payload).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(payload, cell.payload)
      self.assertEqual(b'', cell.unused)  # always empty
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

    empty_constructed_cell = VPaddingCell(size = 0)
    self.assertEqual(VPADDING_CELL_EMPTY_PACKED, empty_constructed_cell.pack(2))
    self.assertEqual(b'', empty_constructed_cell.payload)

    self.assertRaisesWith(ValueError, 'VPaddingCell constructor specified both a size of 5 bytes and payload of 1 bytes', VPaddingCell, 5, '\x02')
    self.assertRaisesWith(ValueError, 'VPaddingCell size (-15) cannot be negative', VPaddingCell, -15)
    self.assertRaisesWith(ValueError, 'VPaddingCell constructor must specify payload or size', VPaddingCell)

  def test_certs_cell(self):
    for cell_bytes, (certs, unused, link_protocol) in CERTS_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, CertsCell(certs).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, CertsCell(certs, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(certs, cell.certificates)
      self.assertEqual(unused, cell.unused)
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

    # truncated or missing certificates should error

    self.assertRaisesWith(ValueError, 'CERTS cell should have a certificate with 3 bytes, but only had 1 remaining', Cell.pop, b'\x00\x00\x81\x00\x05\x01\x01\x00\x03\x08', 2)
    self.assertRaisesWith(ValueError, 'CERTS cell indicates it should have 2 certificates, but only contained 1', Cell.pop, b'\x00\x00\x81\x00\x05\x02\x01\x00\x01\x08', 2)

  def test_auth_challenge_cell(self):
    for cell_bytes, (challenge, methods, unused, link_protocol) in AUTH_CHALLENGE_CELLS.items():
      if not unused.strip(ZERO):
        self.assertEqual(cell_bytes, AuthChallengeCell(methods, challenge).pack(link_protocol))
      else:
        self.assertEqual(cell_bytes, AuthChallengeCell(methods, challenge, unused = unused).pack(link_protocol))

      cell = Cell.pop(cell_bytes, link_protocol)[0]
      self.assertEqual(challenge, cell.challenge)
      self.assertEqual(methods, cell.methods)
      self.assertEqual(unused, cell.unused)
      self.assertEqual(cell_bytes, cell.pack(link_protocol))

    self.assertRaisesWith(ValueError, 'AUTH_CHALLENGE cell should have a payload of 38 bytes, but only had 16', Cell.pop, b'\x00\x00\x82\x00&' + CHALLENGE[:10] + b'\x00\x02\x00\x01\x00\x03', 2)
    self.assertRaisesWith(ValueError, 'AUTH_CHALLENGE should have 3 methods, but only had 4 bytes for it', Cell.pop, b'\x00\x00\x82\x00&' + CHALLENGE + b'\x00\x03\x00\x01\x00\x03', 2)
