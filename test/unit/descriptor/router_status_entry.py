"""
Unit tests for stem.descriptor.router_status_entry.
"""

import datetime
import unittest

import stem.descriptor

from stem import Flag
from stem.descriptor.router_status_entry import RouterStatusEntryV3, _base64_to_hex
from stem.exit_policy import MicroExitPolicy
from stem.version import Version

from test.unit.descriptor import get_resource

from test.mocking import (
  get_router_status_entry_v2,
  get_router_status_entry_v3,
  get_router_status_entry_micro_v3,
  ROUTER_STATUS_ENTRY_V3_HEADER,
)

ENTRY_WITHOUT_ED25519 = """\
r seele AAoQ1DAR6kkoo19hBAX5K0QztNw m0ynPuwzSextzsiXYJYA0Hce+Cs 2015-08-23 00:26:35 73.15.150.172 9001 0
s Running Stable Valid
v Tor 0.2.6.10
w Bandwidth=102 Measured=31
p reject 1-65535
id ed25519 none
m 13,14,15 sha256=uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc
m 16,17 sha256=G6FmPe/ehgfb6tsRzFKDCwvvae+RICeP1MaP0vWDGyI
m 18,19,20,21 sha256=/XhIMOnhElo2UiKjL2S10uRka/fhg1CFfNd+9wgUwEE
"""

ENTRY_WITH_ED25519 = """\
r PDrelay1 AAFJ5u9xAqrKlpDW6N0pMhJLlKs yrJ6b/73pmHBiwsREgw+inf8WFw 2015-08-23 16:52:37 95.215.44.189 8080 0
s Fast Running Stable Valid
v Tor 0.2.7.2-alpha-dev
w Bandwidth=608 Measured=472
p reject 1-65535
id ed25519 8RH34kO07Pp+XYwzdoATVyCibIvmbslUjRkAm7J4IA8
m 13 sha256=PTSHzE7RKnRGZMRmBddSzDiZio254FUhv9+V4F5zq8s
m 14,15 sha256=0wsEwBbxJ8RtPmGYwilHQTVEw2pWzUBEVlSgEO77OyU
m 16,17 sha256=JK2xhYr/VsCF60px+LsT990BCpfKfQTeMxRbD63o2vE
m 18,19,20 sha256=AkZH3gIvz3wunsroqh5izBJizdYuR7kn2oVbsvqgML8
m 21 sha256=AVp41YVxKEJCaoEf0+77Cdvyw5YgpyDXdob0+LSv/pE
"""


def vote_document():
  class Stub(object):
    pass

  mock_document = Stub()  # just need anything with a __dict__
  setattr(mock_document, 'is_vote', True)
  setattr(mock_document, 'is_consensus', False)
  return mock_document


class TestRouterStatusEntry(unittest.TestCase):
  def test_fingerprint_decoding(self):
    """
    Tests for the _base64_to_hex() helper.
    """

    # consensus identity field and fingerprint for caerSidi and Amunet1-5
    test_values = {
      'p1aag7VwarGxqctS7/fS0y5FU+s': 'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB',
      'IbhGa8T+8tyy/MhxCk/qI+EI2LU': '21B8466BC4FEF2DCB2FCC8710A4FEA23E108D8B5',
      '20wYcbFGwFfMktmuffYj6Z1RM9k': 'DB4C1871B146C057CC92D9AE7DF623E99D5133D9',
      'nTv9AG1cZeFW2hXiSIEAF6JLRJ4': '9D3BFD006D5C65E156DA15E248810017A24B449E',
      '/UKsQiOSGPi/6es0/ha1prNTeDI': 'FD42AC42239218F8BFE9EB34FE16B5A6B3537832',
      '/nHdqoKZ6bKZixxAPzYt9Qen+Is': 'FE71DDAA8299E9B2998B1C403F362DF507A7F88B',
    }

    for arg, expected in test_values.items():
      self.assertEqual(expected, _base64_to_hex(arg, True))

    # checks with some malformed inputs
    for arg in ('', '20wYcb', '20wYcb' * 30):
      self.assertRaises(ValueError, _base64_to_hex, arg, True)

  def test_minimal_v2(self):
    """
    Parses a minimal v2 router status entry.
    """

    entry = get_router_status_entry_v2()

    self.assertEqual(None, entry.document)
    self.assertEqual('caerSidi', entry.nickname)
    self.assertEqual('A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB', entry.fingerprint)
    self.assertEqual('A106452D87BD7B803B6CE916291ED368DC5BD091', entry.digest)
    self.assertEqual(datetime.datetime(2012, 8, 6, 11, 19, 31), entry.published)
    self.assertEqual('71.35.150.29', entry.address)
    self.assertEqual(9001, entry.or_port)
    self.assertEqual(None, entry.dir_port)
    self.assertEqual(None, entry.flags)
    self.assertEqual(None, entry.version_line)
    self.assertEqual(None, entry.version)
    self.assertEqual([], entry.get_unrecognized_lines())

  def test_minimal_v3(self):
    """
    Parses a minimal v3 router status entry.
    """

    entry = get_router_status_entry_v3()

    expected_flags = set([Flag.FAST, Flag.NAMED, Flag.RUNNING, Flag.STABLE, Flag.VALID])
    self.assertEqual(None, entry.document)
    self.assertEqual('caerSidi', entry.nickname)
    self.assertEqual('A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB', entry.fingerprint)
    self.assertEqual('A106452D87BD7B803B6CE916291ED368DC5BD091', entry.digest)
    self.assertEqual(datetime.datetime(2012, 8, 6, 11, 19, 31), entry.published)
    self.assertEqual('71.35.150.29', entry.address)
    self.assertEqual(9001, entry.or_port)
    self.assertEqual(None, entry.dir_port)
    self.assertEqual(expected_flags, set(entry.flags))
    self.assertEqual(None, entry.version_line)
    self.assertEqual(None, entry.version)
    self.assertEqual(None, entry.bandwidth)
    self.assertEqual(None, entry.measured)
    self.assertEqual(False, entry.is_unmeasured)
    self.assertEqual([], entry.unrecognized_bandwidth_entries)
    self.assertEqual(None, entry.exit_policy)
    self.assertEqual([], entry.microdescriptor_hashes)
    self.assertEqual(None, entry.identifier_type)
    self.assertEqual(None, entry.identifier)
    self.assertEqual([], entry.get_unrecognized_lines())

  def test_minimal_micro_v3(self):
    """
    Parses a minimal microdescriptor v3 router status entry.
    """

    entry = get_router_status_entry_micro_v3()

    expected_flags = set([Flag.FAST, Flag.GUARD, Flag.HSDIR, Flag.NAMED, Flag.RUNNING, Flag.STABLE, Flag.V2DIR, Flag.VALID])
    self.assertEqual(None, entry.document)
    self.assertEqual('Konata', entry.nickname)
    self.assertEqual('011209176CDBAA2AC1F48C2C5B4990CE771C5B0C', entry.fingerprint)
    self.assertEqual(datetime.datetime(2012, 9, 24, 13, 40, 40), entry.published)
    self.assertEqual('69.64.48.168', entry.address)
    self.assertEqual(9001, entry.or_port)
    self.assertEqual(9030, entry.dir_port)
    self.assertEqual(expected_flags, set(entry.flags))
    self.assertEqual(None, entry.version_line)
    self.assertEqual(None, entry.version)
    self.assertEqual('6A252497006BB9AF36A1B1B902C4D7FA2129923400DBE0101F167B1B031F63BD', entry.digest)
    self.assertEqual([], entry.get_unrecognized_lines())

  def test_without_ed25519(self):
    """
    Parses a router status entry without a ed25519 value.
    """

    microdescriptor_hashes = [
      ([13, 14, 15], {'sha256': 'uaAYTOVuYRqUwJpNfP2WizjzO0FiNQB4U97xSQu+vMc'}),
      ([16, 17], {'sha256': 'G6FmPe/ehgfb6tsRzFKDCwvvae+RICeP1MaP0vWDGyI'}),
      ([18, 19, 20, 21], {'sha256': '/XhIMOnhElo2UiKjL2S10uRka/fhg1CFfNd+9wgUwEE'}),
    ]

    entry = RouterStatusEntryV3(ENTRY_WITHOUT_ED25519, document = vote_document(), validate = True)
    self.assertEqual('seele', entry.nickname)
    self.assertEqual('000A10D43011EA4928A35F610405F92B4433B4DC', entry.fingerprint)
    self.assertEqual(datetime.datetime(2015, 8, 23, 0, 26, 35), entry.published)
    self.assertEqual('73.15.150.172', entry.address)
    self.assertEqual(9001, entry.or_port)
    self.assertEqual(None, entry.dir_port)
    self.assertEqual(set([Flag.RUNNING, Flag.STABLE, Flag.VALID]), set(entry.flags))
    self.assertEqual('Tor 0.2.6.10', entry.version_line)
    self.assertEqual(Version('0.2.6.10'), entry.version)
    self.assertEqual(102, entry.bandwidth)
    self.assertEqual(31, entry.measured)
    self.assertEqual(False, entry.is_unmeasured)
    self.assertEqual([], entry.unrecognized_bandwidth_entries)
    self.assertEqual(MicroExitPolicy('reject 1-65535'), entry.exit_policy)
    self.assertEqual(microdescriptor_hashes, entry.microdescriptor_hashes)
    self.assertEqual('ed25519', entry.identifier_type)
    self.assertEqual('none', entry.identifier)
    self.assertEqual('9B4CA73EEC3349EC6DCEC897609600D0771EF82B', entry.digest)
    self.assertEqual([], entry.get_unrecognized_lines())

  def test_with_ed25519(self):
    """
    Parses a router status entry with a ed25519 value.
    """

    microdescriptor_hashes = [
      ([13], {'sha256': 'PTSHzE7RKnRGZMRmBddSzDiZio254FUhv9+V4F5zq8s'}),
      ([14, 15], {'sha256': '0wsEwBbxJ8RtPmGYwilHQTVEw2pWzUBEVlSgEO77OyU'}),
      ([16, 17], {'sha256': 'JK2xhYr/VsCF60px+LsT990BCpfKfQTeMxRbD63o2vE'}),
      ([18, 19, 20], {'sha256': 'AkZH3gIvz3wunsroqh5izBJizdYuR7kn2oVbsvqgML8'}),
      ([21], {'sha256': 'AVp41YVxKEJCaoEf0+77Cdvyw5YgpyDXdob0+LSv/pE'}),
    ]

    entry = RouterStatusEntryV3(ENTRY_WITH_ED25519, document = vote_document(), validate = True)
    self.assertEqual('PDrelay1', entry.nickname)
    self.assertEqual('000149E6EF7102AACA9690D6E8DD2932124B94AB', entry.fingerprint)
    self.assertEqual(datetime.datetime(2015, 8, 23, 16, 52, 37), entry.published)
    self.assertEqual('95.215.44.189', entry.address)
    self.assertEqual(8080, entry.or_port)
    self.assertEqual(None, entry.dir_port)
    self.assertEqual(set([Flag.FAST, Flag.RUNNING, Flag.STABLE, Flag.VALID]), set(entry.flags))
    self.assertEqual('Tor 0.2.7.2-alpha-dev', entry.version_line)
    self.assertEqual(Version('0.2.7.2-alpha-dev'), entry.version)
    self.assertEqual(608, entry.bandwidth)
    self.assertEqual(472, entry.measured)
    self.assertEqual(False, entry.is_unmeasured)
    self.assertEqual([], entry.unrecognized_bandwidth_entries)
    self.assertEqual(MicroExitPolicy('reject 1-65535'), entry.exit_policy)
    self.assertEqual(microdescriptor_hashes, entry.microdescriptor_hashes)
    self.assertEqual('ed25519', entry.identifier_type)
    self.assertEqual('8RH34kO07Pp+XYwzdoATVyCibIvmbslUjRkAm7J4IA8', entry.identifier)
    self.assertEqual('CAB27A6FFEF7A661C18B0B11120C3E8A77FC585C', entry.digest)
    self.assertEqual([], entry.get_unrecognized_lines())

  def test_missing_fields(self):
    """
    Parses a router status entry that's missing fields.
    """

    content = get_router_status_entry_v3(exclude = ('r', 's'), content = True)
    self._expect_invalid_attr(content, 'address')

    content = get_router_status_entry_v3(exclude = ('r',), content = True)
    self._expect_invalid_attr(content, 'address')

    content = get_router_status_entry_v3(exclude = ('s',), content = True)
    self._expect_invalid_attr(content, 'flags')

  def test_unrecognized_lines(self):
    """
    Parses a router status entry with new keywords.
    """

    entry = get_router_status_entry_v3({'z': 'New tor feature: sparkly unicorns!'})
    self.assertEqual(['z New tor feature: sparkly unicorns!'], entry.get_unrecognized_lines())

  def test_proceeding_line(self):
    """
    Includes content prior to the 'r' line.
    """

    content = b'z some stuff\n' + get_router_status_entry_v3(content = True)
    self.assertRaises(ValueError, RouterStatusEntryV3, content, True)
    self.assertEqual(['z some stuff'], RouterStatusEntryV3(content, False).get_unrecognized_lines())

  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """

    content = get_router_status_entry_v3(content = True) + b'\n\nv Tor 0.2.2.35\n\n'
    entry = RouterStatusEntryV3(content)
    self.assertEqual('Tor 0.2.2.35', entry.version_line)

  def test_duplicate_lines(self):
    """
    Duplicates linesin the entry.
    """

    lines = get_router_status_entry_v3(content = True).split(b'\n')

    for index, duplicate_line in enumerate(lines):
      content = b'\n'.join(lines[:index] + [duplicate_line] + lines[index:])
      self.assertRaises(ValueError, RouterStatusEntryV3, content, True)

      entry = RouterStatusEntryV3(content, False)
      self.assertEqual('caerSidi', entry.nickname)

  def test_missing_r_field(self):
    """
    Excludes fields from the 'r' line.
    """

    components = (
      ('nickname', 'caerSidi'),
      ('fingerprint', 'p1aag7VwarGxqctS7/fS0y5FU+s'),
      ('digest', 'oQZFLYe9e4A7bOkWKR7TaNxb0JE'),
      ('published', '2012-08-06 11:19:31'),
      ('address', '71.35.150.29'),
      ('or_port', '9001'),
      ('dir_port', '0'),
    )

    for attr, value in components:
      # construct the 'r' line without this field
      test_components = [comp[1] for comp in components]
      test_components.remove(value)
      r_line = ' '.join(test_components)

      content = get_router_status_entry_v3({'r': r_line}, content = True)
      self._expect_invalid_attr(content, attr)

  def test_malformed_nickname(self):
    """
    Parses an 'r' line with a malformed nickname.
    """

    test_values = (
      '',
      'saberrider2008ReallyLongNickname',  # too long
      '$aberrider2008',  # invalid characters
    )

    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1].replace('caerSidi', value)
      content = get_router_status_entry_v3({'r': r_line}, content = True)

      # TODO: Initial whitespace is consumed as part of the keyword/value
      # divider. This is a bug in the case of V3 router status entries, but
      # proper behavior for V2 router status entries and server/extrainfo
      # descriptors.
      #
      # I'm inclined to leave this as-is for the moment since fixing it
      # requires special KEYWORD_LINE handling, and the only result of this bug
      # is that our validation doesn't catch the new SP restriction on V3
      # entries.

      if value == '':
        value = None

      self._expect_invalid_attr(content, 'nickname')

  def test_malformed_fingerprint(self):
    """
    Parses an 'r' line with a malformed fingerprint.
    """

    test_values = (
      '',
      'zzzzz',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    )

    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1].replace('p1aag7VwarGxqctS7/fS0y5FU+s', value)
      content = get_router_status_entry_v3({'r': r_line}, content = True)
      self._expect_invalid_attr(content, 'fingerprint')

  def test_malformed_published_date(self):
    """
    Parses an 'r' line with a malformed published date.
    """

    test_values = (
      '',
      '2012-08-06 11:19:',
      '2012-08-06 11:19:71',
      '2012-08-06 11::31',
      '2012-08-06 11:79:31',
      '2012-08-06 :19:31',
      '2012-08-06 41:19:31',
      '2012-08- 11:19:31',
      '2012-08-86 11:19:31',
      '2012--06 11:19:31',
      '2012-38-06 11:19:31',
      '-08-06 11:19:31',
      '2012-08-06   11:19:31',
    )

    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1].replace('2012-08-06 11:19:31', value)
      content = get_router_status_entry_v3({'r': r_line}, content = True)
      self._expect_invalid_attr(content, 'published')

  def test_malformed_address(self):
    """
    Parses an 'r' line with a malformed address.
    """

    test_values = (
      '',
      '71.35.150.',
      '71.35..29',
      '71.35.150',
      '71.35.150.256',
    )

    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1].replace('71.35.150.29', value)
      content = get_router_status_entry_v3({'r': r_line}, content = True)
      self._expect_invalid_attr(content, 'address')

  def test_malformed_port(self):
    """
    Parses an 'r' line with a malformed ORPort or DirPort.
    """

    test_values = (
      '',
      '-1',
      '399482',
      'blarg',
    )

    for value in test_values:
      for include_or_port in (False, True):
        for include_dir_port in (False, True):
          if not include_or_port and not include_dir_port:
            continue

          r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1]

          if include_or_port:
            r_line = r_line.replace(' 9001 ', ' %s ' % value)

          if include_dir_port:
            r_line = r_line[:-1] + value

          attr = 'or_port' if include_or_port else 'dir_port'

          content = get_router_status_entry_v3({'r': r_line}, content = True)
          self._expect_invalid_attr(content, attr)

  def test_ipv6_addresses(self):
    """
    Handles a variety of 'a' lines.
    """

    test_values = {
      '[2607:fcd0:daaa:101::602c:bd62]:443': [
        ('2607:fcd0:daaa:101::602c:bd62', 443, True)],
    }

    for a_line, expected in test_values.items():
      entry = get_router_status_entry_v3({'a': a_line})
      self.assertEqual(expected, entry.or_addresses)

    # includes multiple 'a' lines

    content = get_router_status_entry_v3(content = True)
    content += b'\na [2607:fcd0:daaa:101::602c:bd62]:443'
    content += b'\na [1148:fcd0:daaa:101::602c:bd62]:80'

    expected = [
      ('2607:fcd0:daaa:101::602c:bd62', 443, True),
      ('1148:fcd0:daaa:101::602c:bd62', 80, True),
    ]

    entry = RouterStatusEntryV3(content)
    self.assertEqual(expected, entry.or_addresses)

    # tries some invalid inputs

    test_values = (
      '',
      '[1148:fcd0:daaa:101::602c:bd62]:80000',
    )

    for a_line in test_values:
      content = get_router_status_entry_v3({'a': a_line}, content = True)
      self._expect_invalid_attr(content, expected_value = {})

  def test_flags(self):
    """
    Handles a variety of flag inputs.
    """

    test_values = {
      '': [],
      'Fast': [Flag.FAST],
      'Fast Valid': [Flag.FAST, Flag.VALID],
      'Ugabuga': ['Ugabuga'],
    }

    for s_line, expected in test_values.items():
      entry = get_router_status_entry_v3({'s': s_line})
      self.assertEqual(expected, entry.flags)

    # tries some invalid inputs
    test_values = {
      'Fast   ': [Flag.FAST, '', '', ''],
      'Fast  Valid': [Flag.FAST, '', Flag.VALID],
      'Fast Fast': [Flag.FAST, Flag.FAST],
    }

    for s_line, expected in test_values.items():
      content = get_router_status_entry_v3({'s': s_line}, content = True)
      self._expect_invalid_attr(content, 'flags', expected)

  def test_versions(self):
    """
    Handles a variety of version inputs.
    """

    test_values = {
      'Tor 0.2.2.35': Version('0.2.2.35'),
      'Tor 0.1.2': Version('0.1.2'),
      'Torr new_stuff': None,
      'new_stuff and stuff': None,
    }

    for v_line, expected in test_values.items():
      entry = get_router_status_entry_v3({'v': v_line})
      self.assertEqual(expected, entry.version)
      self.assertEqual(v_line, entry.version_line)

    # tries an invalid input
    content = get_router_status_entry_v3({'v': 'Tor ugabuga'}, content = True)
    self._expect_invalid_attr(content, 'version')

  def test_bandwidth(self):
    """
    Handles a variety of 'w' lines.
    """

    test_values = {
      'Bandwidth=0': (0, None, False, []),
      'Bandwidth=63138': (63138, None, False, []),
      'Bandwidth=11111 Measured=482': (11111, 482, False, []),
      'Bandwidth=11111 Measured=482 Blarg!': (11111, 482, False, ['Blarg!']),
      'Bandwidth=11111 Measured=482 Unmeasured=1 Blarg!': (11111, 482, True, ['Blarg!']),
    }

    for w_line, expected in test_values.items():
      entry = get_router_status_entry_v3({'w': w_line})
      self.assertEqual(expected[0], entry.bandwidth)
      self.assertEqual(expected[1], entry.measured)
      self.assertEqual(expected[2], entry.is_unmeasured)
      self.assertEqual(expected[3], entry.unrecognized_bandwidth_entries)

    # tries some invalid inputs
    test_values = (
      '',
      'blarg',
      'Bandwidth',
      'Bandwidth=',
      'Bandwidth:0',
      'Bandwidth 0',
      'Bandwidth=-10',
      'Bandwidth=10 Measured',
      'Bandwidth=10 Measured=',
      'Bandwidth=10 Measured=-50',
      'Bandwidth=10 Measured=482 Unmeasured',
      'Bandwidth=10 Measured=482 Unmeasured=',
      'Bandwidth=10 Measured=482 Unmeasured=0',
      'Bandwidth=10 Measured=482 Unmeasured=842',
      'Bandwidth=10 Measured=482 Unmeasured=-5',
    )

    for w_line in test_values:
      content = get_router_status_entry_v3({'w': w_line}, content = True)
      self._expect_invalid_attr(content)

  def test_exit_policy(self):
    """
    Handles a variety of 'p' lines.
    """

    test_values = {
      'reject 1-65535': MicroExitPolicy('reject 1-65535'),
      'accept 80,110,143,443': MicroExitPolicy('accept 80,110,143,443'),
    }

    for p_line, expected in test_values.items():
      entry = get_router_status_entry_v3({'p': p_line})
      self.assertEqual(expected, entry.exit_policy)

    # tries some invalid inputs
    test_values = (
      '',
      'blarg',
      'reject -50',
      'accept 80,',
    )

    for p_line in test_values:
      content = get_router_status_entry_v3({'p': p_line}, content = True)
      self._expect_invalid_attr(content, 'exit_policy')

  def test_microdescriptor_hashes(self):
    """
    Handles a variety of 'm' lines.
    """

    test_values = {
      '8,9,10,11,12':
        [([8, 9, 10, 11, 12], {})],
      '8,9,10,11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs':
        [([8, 9, 10, 11, 12], {'sha256': 'g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs'})],
      '8,9,10,11,12 sha256=g1vx9si329muxV md5=3tquWIXXySNOIwRGMeAESKs/v4DWs':
        [([8, 9, 10, 11, 12], {'sha256': 'g1vx9si329muxV', 'md5': '3tquWIXXySNOIwRGMeAESKs/v4DWs'})],
    }

    for m_line, expected in test_values.items():
      content = get_router_status_entry_v3({'m': m_line}, content = True)
      entry = RouterStatusEntryV3(content, document = vote_document())
      self.assertEqual(expected, entry.microdescriptor_hashes)

    # try with multiple 'm' lines

    content = get_router_status_entry_v3(content = True)
    content += b'\nm 11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs'
    content += b'\nm 31,32 sha512=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs'

    expected = [
      ([11, 12], {'sha256': 'g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs'}),
      ([31, 32], {'sha512': 'g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs'}),
    ]

    entry = RouterStatusEntryV3(content, document = vote_document())
    self.assertEqual(expected, entry.microdescriptor_hashes)

    # try without a document
    content = get_router_status_entry_v3({'m': '8,9,10,11,12'}, content = True)
    self._expect_invalid_attr(content, 'microdescriptor_hashes', expected_value = [])

    # tries some invalid inputs
    test_values = (
      '',
      '4,a,2',
      '1,2,3 stuff',
    )

    for m_line in test_values:
      content = get_router_status_entry_v3({'m': m_line}, content = True)
      self.assertRaises(ValueError, RouterStatusEntryV3, content, True, vote_document())

  def test_with_carriage_returns(self):
    """
    Read a descriptor file with windows newlines (CRLF).
    """

    descriptor_path = get_resource('cached-microdesc-consensus_with_carriage_returns')

    with open(descriptor_path, 'rb') as descriptor_file:
      descriptors = stem.descriptor.parse_file(descriptor_file, 'network-status-microdesc-consensus-3 1.0', normalize_newlines = True)

      # if we didn't strip \r then it would be part of the last flag

      router = next(descriptors)
      self.assertEqual([Flag.FAST, Flag.RUNNING, Flag.STABLE, Flag.VALID], router.flags)

  def _expect_invalid_attr(self, content, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to content having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """

    self.assertRaises(ValueError, RouterStatusEntryV3, content, True)
    entry = RouterStatusEntryV3(content, False)

    if attr:
      self.assertEqual(expected_value, getattr(entry, attr))
    else:
      self.assertEqual('caerSidi', entry.nickname)
