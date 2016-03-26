"""
Unit tests for stem.descriptor.extrainfo_descriptor.
"""

import datetime
import unittest

import stem.descriptor

from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor, DirResponse, DirStat

from test.mocking import get_relay_extrainfo_descriptor, get_bridge_extrainfo_descriptor, CRYPTO_BLOB

from test.unit.descriptor import get_resource


class TestExtraInfoDescriptor(unittest.TestCase):
  def test_metrics_relay_descriptor(self):
    """
    Parses and checks our results against an extrainfo descriptor from metrics.
    """

    descriptor_file = open(get_resource('extrainfo_relay_descriptor'), 'rb')

    expected_signature = """-----BEGIN SIGNATURE-----
K5FSywk7qvw/boA4DQcqkls6Ize5vcBYfhQ8JnOeRQC9+uDxbnpm3qaYN9jZ8myj
k0d2aofcVbHr4fPQOSST0LXDrhFl5Fqo5um296zpJGvRUeO6S44U/EfJAGShtqWw
7LZqklu+gVvhMKREpchVqlAwXkWR44VENm24Hs+mT3M=
-----END SIGNATURE-----"""

    desc = next(stem.descriptor.parse_file(descriptor_file, 'extra-info 1.0'))
    self.assertEqual('NINJA', desc.nickname)
    self.assertEqual('B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48', desc.fingerprint)
    self.assertEqual(datetime.datetime(2012, 5, 5, 17, 3, 50), desc.published)
    self.assertEqual(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.read_history_end)
    self.assertEqual(900, desc.read_history_interval)
    self.assertEqual(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.write_history_end)
    self.assertEqual(900, desc.write_history_interval)
    self.assertEqual(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.dir_read_history_end)
    self.assertEqual(900, desc.dir_read_history_interval)
    self.assertEqual(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.dir_write_history_end)
    self.assertEqual(900, desc.dir_write_history_interval)
    self.assertEqual(expected_signature, desc.signature)
    self.assertEqual('00A57A9AAB5EA113898E2DD02A755E31AFC27227', desc.digest())
    self.assertEqual([], desc.get_unrecognized_lines())

    # The read-history, write-history, dirreq-read-history, and
    # dirreq-write-history lines are pretty long so just checking
    # the initial contents for the line and parsed values.

    read_values_start = [3309568, 9216, 41984, 27648, 123904]
    self.assertEqual(read_values_start, desc.read_history_values[:5])

    write_values_start = [1082368, 19456, 50176, 272384, 485376]
    self.assertEqual(write_values_start, desc.write_history_values[:5])

    dir_read_values_start = [0, 0, 0, 0, 33792, 27648, 48128]
    self.assertEqual(dir_read_values_start, desc.dir_read_history_values[:7])

    dir_write_values_start = [0, 0, 0, 227328, 349184, 382976, 738304]
    self.assertEqual(dir_write_values_start, desc.dir_write_history_values[:7])

  def test_metrics_bridge_descriptor(self):
    """
    Parses and checks our results against an extrainfo bridge descriptor from
    metrics.
    """

    descriptor_file = open(get_resource('extrainfo_bridge_descriptor'), 'rb')

    expected_dir_v2_responses = {
      DirResponse.OK: 0,
      DirResponse.UNAVAILABLE: 0,
      DirResponse.NOT_FOUND: 0,
      DirResponse.NOT_MODIFIED: 0,
      DirResponse.BUSY: 0,
    }

    expected_dir_v3_responses = {
      DirResponse.OK: 72,
      DirResponse.NOT_ENOUGH_SIGS: 0,
      DirResponse.UNAVAILABLE: 0,
      DirResponse.NOT_FOUND: 0,
      DirResponse.NOT_MODIFIED: 0,
      DirResponse.BUSY: 0,
    }

    desc = next(stem.descriptor.parse_file(descriptor_file, 'bridge-extra-info 1.0'))
    self.assertEqual('ec2bridgereaac65a3', desc.nickname)
    self.assertEqual('1EC248422B57D9C0BD751892FE787585407479A4', desc.fingerprint)
    self.assertEqual(datetime.datetime(2012, 6, 8, 2, 21, 27), desc.published)
    self.assertEqual(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.read_history_end)
    self.assertEqual(900, desc.read_history_interval)
    self.assertEqual(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.write_history_end)
    self.assertEqual(900, desc.write_history_interval)
    self.assertEqual(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.dir_read_history_end)
    self.assertEqual(900, desc.dir_read_history_interval)
    self.assertEqual(datetime.datetime(2012, 6, 8, 2, 10, 38), desc.dir_write_history_end)
    self.assertEqual(900, desc.dir_write_history_interval)
    self.assertEqual('00A2AECCEAD3FEE033CFE29893387143146728EC', desc.digest())
    self.assertEqual([], desc.get_unrecognized_lines())

    read_values_start = [337920, 437248, 3995648, 48726016]
    self.assertEqual(read_values_start, desc.read_history_values[:4])

    write_values_start = [343040, 991232, 5649408, 49548288]
    self.assertEqual(write_values_start, desc.write_history_values[:4])

    dir_read_values_start = [0, 71680, 99328, 25600]
    self.assertEqual(dir_read_values_start, desc.dir_read_history_values[:4])

    dir_write_values_start = [5120, 664576, 2419712, 578560]
    self.assertEqual(dir_write_values_start, desc.dir_write_history_values[:4])

    self.assertEqual({}, desc.dir_v2_requests)
    self.assertEqual({}, desc.dir_v3_requests)

    self.assertEqual(expected_dir_v2_responses, desc.dir_v2_responses)
    self.assertEqual(expected_dir_v3_responses, desc.dir_v3_responses)

    self.assertEqual({}, desc.dir_v2_responses_unknown)
    self.assertEqual({}, desc.dir_v2_responses_unknown)

  def test_multiple_metrics_bridge_descriptors(self):
    """
    Check that we can read bridge descriptors when there's multiple in a file.
    """

    descriptor_file = open(get_resource('extrainfo_bridge_descriptor_multiple'), 'rb')
    desc_list = list(stem.descriptor.parse_file(descriptor_file))

    self.assertEqual(6, len(desc_list))
    self.assertEqual('909B07DB17E21D263C55794AB815BF1DB195FDD9', desc_list[0].fingerprint)
    self.assertEqual('7F7798A3CBB0F643B1CFCE3FD4F2B7C553764498', desc_list[1].fingerprint)
    self.assertEqual('B4869206C1EEA4A090FE614155BD6942701F80F1', desc_list[2].fingerprint)
    self.assertEqual('C18896EB6274DC8123491FAE1DD17E1769C54C4F', desc_list[3].fingerprint)
    self.assertEqual('478B4CB438302981DE9AAF246F48DBE57F69050A', desc_list[4].fingerprint)
    self.assertEqual('25D9D52A0350B42E69C8AB7CE945DB1CA38DA0CF', desc_list[5].fingerprint)

  def test_with_ed25519(self):
    """
    Parses a descriptor with a ed25519 identity key.
    """

    with open(get_resource('extrainfo_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = True))

    self.assertEqual('silverfoxden', desc.nickname)
    self.assertEqual('4970B1DC3DBC8D82D7F1E43FF44B28DBF4765A4E', desc.fingerprint)
    self.assertTrue('AQQABhz0AQFcf5tGWLvPvr' in desc.ed25519_certificate)
    self.assertEqual('g6Zg7Er8K7C1etmt7p20INE1ExIvMRPvhwt6sjbLqEK+EtQq8hT+86hQ1xu7cnz6bHee+Zhhmcc4JamV4eiMAw', desc.ed25519_signature)
    self.assertEqual([], desc.get_unrecognized_lines())

  def test_bridge_with_ed25519(self):
    """
    Parses a bridge descriptor with a ed25519 identity key.
    """

    with open(get_resource('bridge_extrainfo_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = True))

    self.assertEqual('Unnamed', desc.nickname)
    self.assertEqual('B8AB331047F1C1637EFE07FB1B94CCC0FE0ABFFA', desc.fingerprint)
    self.assertFalse(hasattr(desc, 'ed25519_certificate'))
    self.assertEqual('VigmhxML9uw8CT1XeGqZ8KLMhKk6AOKnChQt24usBbI', desc.ed25519_certificate_hash)
    self.assertEqual('7DSOQz9eGgjDX6GT7qcrVViK8yqJD4aoEnuhdAgYtgA', desc.router_digest_sha256)
    self.assertEqual([], desc.get_unrecognized_lines())

  def test_nonascii_v3_reqs(self):
    """
    Malformed descriptor with non-ascii content for the 'dirreq-v3-reqs' line.
    """

    with open(get_resource('extrainfo_nonascii_v3_reqs'), 'rb') as descriptor_file:
      try:
        next(stem.descriptor.parse_file(descriptor_file, 'extra-info 1.0', validate = True))
        self.fail("validation should've raised an exception")
      except ValueError as exc:
        expected = "'dirreq-v3-reqs' line had non-ascii content: S?=4026597208,S?=4026597208,S?=4026597208,S?=4026597208,S?=4026597208,S?=4026597208,??=4026591624,6?=4026537520,6?=4026537520,6?=4026537520,us=8"
        self.assertEqual(expected, str(exc))

  def test_minimal_extrainfo_descriptor(self):
    """
    Basic sanity check that we can parse an extrainfo descriptor with minimal
    attributes.
    """

    desc = get_relay_extrainfo_descriptor()

    self.assertEqual('ninja', desc.nickname)
    self.assertEqual('B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48', desc.fingerprint)
    self.assertTrue(CRYPTO_BLOB in desc.signature)

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    desc = get_relay_extrainfo_descriptor({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], desc.get_unrecognized_lines())

  def test_proceeding_line(self):
    """
    Includes a line prior to the 'extra-info' entry.
    """

    desc_text = b'exit-streams-opened port=80\n' + get_relay_extrainfo_descriptor(content = True)
    self._expect_invalid_attr(desc_text)

  def test_trailing_line(self):
    """
    Includes a line after the 'router-signature' entry.
    """

    desc_text = get_relay_extrainfo_descriptor(content = True) + b'\nexit-streams-opened port=80'
    self._expect_invalid_attr(desc_text)

  def test_extrainfo_line_missing_fields(self):
    """
    Checks that validation catches when the extra-info line is missing fields
    and that without validation both the nickname and fingerprint are left as
    None.
    """

    test_entries = (
      'ninja',
      'ninja ',
      'B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48',
      ' B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48',
    )

    for entry in test_entries:
      desc_text = get_relay_extrainfo_descriptor({'extra-info': entry}, content = True)
      desc = self._expect_invalid_attr(desc_text, 'nickname')
      self.assertEqual(None, desc.nickname)
      self.assertEqual(None, desc.fingerprint)

  def test_geoip_db_digest(self):
    """
    Parses the geoip-db-digest and geoip6-db-digest lines with valid and
    invalid data.
    """

    geoip_db_digest = '916A3CA8B7DF61473D5AE5B21711F35F301CE9E8'
    desc = get_relay_extrainfo_descriptor({'geoip-db-digest': geoip_db_digest})
    self.assertEqual(geoip_db_digest, desc.geoip_db_digest)

    desc = get_relay_extrainfo_descriptor({'geoip6-db-digest': geoip_db_digest})
    self.assertEqual(geoip_db_digest, desc.geoip6_db_digest)

    test_entries = (
      '',
      '916A3CA8B7DF61473D5AE5B21711F35F301CE9E',
      '916A3CA8B7DF61473D5AE5B21711F35F301CE9E88',
      '916A3CA8B7DF61473D5AE5B21711F35F301CE9EG',
      '916A3CA8B7DF61473D5AE5B21711F35F301CE9E-',
    )

    for entry in test_entries:
      desc_text = get_relay_extrainfo_descriptor({'geoip-db-digest': entry}, content = True)
      self._expect_invalid_attr(desc_text, 'geoip_db_digest')

      desc_text = get_relay_extrainfo_descriptor({'geoip6-db-digest': entry}, content = True)
      self._expect_invalid_attr(desc_text, 'geoip6_db_digest')

  def test_cell_circuits_per_decile(self):
    """
    Parses the cell-circuits-per-decile line with valid and invalid data.
    """

    test_entries = (
      ('0', 0),
      ('11', 11),
    )

    for entry in ('0', '11', '25'):
      desc = get_relay_extrainfo_descriptor({'cell-circuits-per-decile': entry})
      self.assertEqual(int(entry), desc.cell_circuits_per_decile)

    test_entries = (
      '',
      ' ',
      '-5',
      'blarg',
    )

    for entry in test_entries:
      desc_text = get_relay_extrainfo_descriptor({'cell-circuits-per-decile': entry}, content = True)
      self._expect_invalid_attr(desc_text, 'cell_circuits_per_decile')

  def test_dir_response_lines(self):
    """
    Parses the dirreq-v2-resp and dirreq-v3-resp lines with valid and invalid
    data.
    """

    for keyword in ('dirreq-v2-resp', 'dirreq-v3-resp'):
      attr = keyword.replace('-', '_').replace('dirreq', 'dir').replace('resp', 'responses')
      unknown_attr = attr + '_unknown'

      test_value = 'ok=0,unavailable=0,not-found=984,not-modified=0,something-new=7'
      desc = get_relay_extrainfo_descriptor({keyword: test_value})
      self.assertEqual(0, getattr(desc, attr)[DirResponse.OK])
      self.assertEqual(0, getattr(desc, attr)[DirResponse.UNAVAILABLE])
      self.assertEqual(984, getattr(desc, attr)[DirResponse.NOT_FOUND])
      self.assertEqual(0, getattr(desc, attr)[DirResponse.NOT_MODIFIED])
      self.assertEqual(7, getattr(desc, unknown_attr)['something-new'])

      test_entries = (
        'ok=-4',
        'ok:4',
        'ok=4.not-found=3',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        desc = self._expect_invalid_attr(desc_text)
        self.assertEqual(None, getattr(desc, attr))
        self.assertEqual(None, getattr(desc, unknown_attr))

  def test_dir_stat_lines(self):
    """
    Parses the dirreq-v2-direct-dl, dirreq-v3-direct-dl, dirreq-v2-tunneled-dl,
    and dirreq-v3-tunneled-dl lines with valid and invalid data.
    """

    for keyword in ('dirreq-v2-direct-dl', 'dirreq-v2-direct-dl', 'dirreq-v2-tunneled-dl', 'dirreq-v2-tunneled-dl'):
      attr = keyword.replace('-', '_').replace('dirreq', 'dir')
      unknown_attr = attr + '_unknown'

      test_value = 'complete=2712,timeout=32,running=4,min=741,d1=14507,d2=22702,q1=28881,d3=38277,d4=73729,md=111455,d6=168231,d7=257218,q3=319833,d8=390507,d9=616301,something-new=11,max=29917857'
      desc = get_relay_extrainfo_descriptor({keyword: test_value})
      self.assertEqual(2712, getattr(desc, attr)[DirStat.COMPLETE])
      self.assertEqual(32, getattr(desc, attr)[DirStat.TIMEOUT])
      self.assertEqual(4, getattr(desc, attr)[DirStat.RUNNING])
      self.assertEqual(741, getattr(desc, attr)[DirStat.MIN])
      self.assertEqual(14507, getattr(desc, attr)[DirStat.D1])
      self.assertEqual(22702, getattr(desc, attr)[DirStat.D2])
      self.assertEqual(28881, getattr(desc, attr)[DirStat.Q1])
      self.assertEqual(38277, getattr(desc, attr)[DirStat.D3])
      self.assertEqual(73729, getattr(desc, attr)[DirStat.D4])
      self.assertEqual(111455, getattr(desc, attr)[DirStat.MD])
      self.assertEqual(168231, getattr(desc, attr)[DirStat.D6])
      self.assertEqual(257218, getattr(desc, attr)[DirStat.D7])
      self.assertEqual(319833, getattr(desc, attr)[DirStat.Q3])
      self.assertEqual(390507, getattr(desc, attr)[DirStat.D8])
      self.assertEqual(616301, getattr(desc, attr)[DirStat.D9])
      self.assertEqual(29917857, getattr(desc, attr)[DirStat.MAX])
      self.assertEqual(11, getattr(desc, unknown_attr)['something-new'])

      test_entries = (
        'complete=-4',
        'complete:4',
        'complete=4.timeout=3',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        desc = self._expect_invalid_attr(desc_text)
        self.assertEqual(None, getattr(desc, attr))
        self.assertEqual(None, getattr(desc, unknown_attr))

  def test_conn_bi_direct(self):
    """
    Parses the conn-bi-direct line with valid and invalid data.
    """

    desc = get_relay_extrainfo_descriptor({'conn-bi-direct': '2012-05-03 12:07:50 (500 s) 277431,12089,0,2134'})
    self.assertEqual(datetime.datetime(2012, 5, 3, 12, 7, 50), desc.conn_bi_direct_end)
    self.assertEqual(500, desc.conn_bi_direct_interval)
    self.assertEqual(277431, desc.conn_bi_direct_below)
    self.assertEqual(12089, desc.conn_bi_direct_read)
    self.assertEqual(0, desc.conn_bi_direct_write)
    self.assertEqual(2134, desc.conn_bi_direct_both)

    test_entries = (
      '',
      '2012-05-03 ',
      '2012-05-03',
      '2012-05-03 12:07:60 (500 s)',
      '2012-05-03 12:07:50 (500s)',
      '2012-05-03 12:07:50 (500 s',
      '2012-05-03 12:07:50 (500 )',
      '2012-05-03 12:07:50 (500 s)11',
      '2012-05-03 12:07:50 (500 s) 277431,12089,0',
      '2012-05-03 12:07:50 (500 s) 277431,12089,0a,2134',
      '2012-05-03 12:07:50 (500 s) -277431,12089,0,2134',
    )

    for entry in test_entries:
      desc_text = get_relay_extrainfo_descriptor({'conn-bi-direct': entry}, content = True)
      desc = self._expect_invalid_attr(desc_text)
      self.assertEqual(None, desc.conn_bi_direct_end)
      self.assertEqual(None, desc.conn_bi_direct_interval)
      self.assertEqual(None, desc.conn_bi_direct_below)
      self.assertEqual(None, desc.conn_bi_direct_read)
      self.assertEqual(None, desc.conn_bi_direct_write)
      self.assertEqual(None, desc.conn_bi_direct_both)

  def test_percentage_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" num%
    """

    for keyword in ('dirreq-v2-share', 'dirreq-v3-share'):
      attr = keyword.replace('-', '_').replace('dirreq', 'dir')

      test_entries = (
        ('0.00%', 0.0),
        ('0.01%', 0.0001),
        ('50%', 0.5),
        ('100.0%', 1.0),
      )

      for test_value, expected_value in test_entries:
        desc = get_relay_extrainfo_descriptor({keyword: test_value})
        self.assertEqual(expected_value, getattr(desc, attr))

      test_entries = (
        (''),
        (' '),
        ('100'),
        ('-5%'),
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        self._expect_invalid_attr(desc_text, attr)

  def test_number_list_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" num,...,num
    """

    for keyword in ('cell-processed-cells', 'cell-queued-cells', 'cell-time-in-queue'):
      attr = keyword.replace('-', '_')

      test_entries = (
        ('', []),
        (' ', []),
        ('0,0,0', [0.0, 0.0, 0.0]),
        ('2.3,-4.6,8.9,16.12,32.15', [2.3, -4.6, 8.9, 16.12, 32.15]),
      )

      for test_value, expected_value in test_entries:
        desc = get_relay_extrainfo_descriptor({keyword: test_value})
        self.assertEqual(expected_value, getattr(desc, attr))

      test_entries = (
        (',,11', [11.0]),
        ('abc,5.7,def', [5.7]),
        ('blarg', []),
      )

      for entry, expected in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        self._expect_invalid_attr(desc_text, attr, expected)

  def test_timestamp_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" YYYY-MM-DD HH:MM:SS
    """

    for keyword in ('published', 'geoip-start-time'):
      attr = keyword.replace('-', '_')

      desc = get_relay_extrainfo_descriptor({keyword: '2012-05-03 12:07:50'})
      self.assertEqual(datetime.datetime(2012, 5, 3, 12, 7, 50), getattr(desc, attr))

      test_entries = (
        '',
        '2012-05-03 12:07:60',
        '2012-05-03 ',
        '2012-05-03',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        self._expect_invalid_attr(desc_text, attr)

  def test_timestamp_and_interval_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" YYYY-MM-DD HH:MM:SS (NSEC s)
    """

    for keyword in ('cell-stats-end', 'entry-stats-end', 'exit-stats-end', 'bridge-stats-end', 'dirreq-stats-end'):
      end_attr = keyword.replace('-', '_').replace('dirreq', 'dir')
      interval_attr = end_attr[:-4] + '_interval'

      desc = get_relay_extrainfo_descriptor({keyword: '2012-05-03 12:07:50 (500 s)'})
      self.assertEqual(datetime.datetime(2012, 5, 3, 12, 7, 50), getattr(desc, end_attr))
      self.assertEqual(500, getattr(desc, interval_attr))

      test_entries = (
        '',
        '2012-05-03 ',
        '2012-05-03',
        '2012-05-03 12:07:60 (500 s)',
        '2012-05-03 12:07:50 (500s)',
        '2012-05-03 12:07:50 (500 s',
        '2012-05-03 12:07:50 (500 )',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        desc = self._expect_invalid_attr(desc_text)
        self.assertEqual(None, getattr(desc, end_attr))
        self.assertEqual(None, getattr(desc, interval_attr))

  def test_timestamp_interval_and_value_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" YYYY-MM-DD HH:MM:SS (NSEC s) NUM,NUM,NUM,NUM,NUM...
    """

    for keyword in ('read-history', 'write-history', 'dirreq-read-history', 'dirreq-write-history'):
      base_attr = keyword.replace('-', '_').replace('dirreq', 'dir')
      end_attr = base_attr + '_end'
      interval_attr = base_attr + '_interval'
      values_attr = base_attr + '_values'

      test_entries = (
        ('', []),
        (' ', []),
        (' 50,11,5', [50, 11, 5]),
      )

      for test_values, expected_values in test_entries:
        desc = get_relay_extrainfo_descriptor({keyword: '2012-05-03 12:07:50 (500 s)%s' % test_values})
        self.assertEqual(datetime.datetime(2012, 5, 3, 12, 7, 50), getattr(desc, end_attr))
        self.assertEqual(500, getattr(desc, interval_attr))
        self.assertEqual(expected_values, getattr(desc, values_attr))

      test_entries = (
        '',
        '2012-05-03 ',
        '2012-05-03',
        '2012-05-03 12:07:60 (500 s)',
        '2012-05-03 12:07:50 (500s)',
        '2012-05-03 12:07:50 (500 s',
        '2012-05-03 12:07:50 (500 )',
        '2012-05-03 12:07:50 (500 s)11',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        desc = self._expect_invalid_attr(desc_text)
        self.assertEqual(None, getattr(desc, end_attr))
        self.assertEqual(None, getattr(desc, interval_attr))
        self.assertEqual(None, getattr(desc, values_attr))

  def test_port_mapping_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" port=N,port=N,...
    """

    for keyword in ('exit-kibibytes-written', 'exit-kibibytes-read', 'exit-streams-opened'):
      attr = keyword.replace('-', '_')

      test_entries = (
        ('', {}),
        ('443=100,other=111', {443: 100, 'other': 111}),
        ('80=115533759,443=1777,995=690', {80: 115533759, 443: 1777, 995: 690}),
      )

      for test_value, expected_value in test_entries:
        desc = get_relay_extrainfo_descriptor({keyword: test_value})
        self.assertEqual(expected_value, getattr(desc, attr))

      test_entries = (
        '8000000=115533759',
        '-80=115533759',
        '80=-115533759',
        '=115533759',
        '80=',
        '80,115533759',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        self._expect_invalid_attr(desc_text, attr)

  def test_hidden_service_stats_end(self):
    """
    Exercise the hidserv-stats-end, which should be a simple date.
    """

    desc = get_relay_extrainfo_descriptor({'hidserv-stats-end': '2012-05-03 12:07:50'})
    self.assertEqual(datetime.datetime(2012, 5, 3, 12, 7, 50), desc.hs_stats_end)

    test_entries = (
      '',
      '2012',
      '2012-05',
      '2012-05-03',
      '2012-05-03 12',
      '2012-05-03 12:07',
      '2012-05-03 12:07:-50',
    )

    for entry in test_entries:
      desc_text = get_relay_extrainfo_descriptor({'hidserv-stats-end': entry}, content = True)
      self._expect_invalid_attr(desc_text, 'hs_stats_end')

  def test_hidden_service_stats(self):
    """
    Check the 'hidserv-rend-relayed-cells' and 'hidserv-dir-onions-seen', which
    share the same format.
    """

    attributes = (
      ('hidserv-rend-relayed-cells', 'hs_rend_cells', 'hs_rend_cells_attr'),
      ('hidserv-dir-onions-seen', 'hs_dir_onions_seen', 'hs_dir_onions_seen_attr'),
    )

    test_entries = (
      '',
      'hello',
      ' key=value',
      '40 key',
      '40 key value',
      '40 key key=value',
    )

    for keyword, stat_attr, extra_attr in attributes:
      # just the numeric stat (no extra attributes)

      desc = get_relay_extrainfo_descriptor({keyword: '345'})
      self.assertEqual(345, getattr(desc, stat_attr))
      self.assertEqual({}, getattr(desc, extra_attr))

      # values can be negative (#15276)

      desc = get_relay_extrainfo_descriptor({keyword: '-345'})
      self.assertEqual(-345, getattr(desc, stat_attr))
      self.assertEqual({}, getattr(desc, extra_attr))

      # with extra attributes

      desc = get_relay_extrainfo_descriptor({keyword: '345 spiffy=true snowmen=neat'})
      self.assertEqual(345, getattr(desc, stat_attr))
      self.assertEqual({'spiffy': 'true', 'snowmen': 'neat'}, getattr(desc, extra_attr))

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        self._expect_invalid_attr(desc_text, stat_attr)
        self._expect_invalid_attr(desc_text, extra_attr, {})

  def test_locale_mapping_lines(self):
    """
    Uses valid and invalid data to tests lines of the form...
    "<keyword>" CC=N,CC=N,...
    """

    for keyword in ('dirreq-v2-ips', 'dirreq-v3-ips', 'dirreq-v2-reqs', 'dirreq-v3-reqs', 'geoip-client-origins', 'entry-ips', 'bridge-ips'):
      attr = keyword.replace('-', '_').replace('dirreq', 'dir').replace('reqs', 'requests')

      test_entries = (
        ('', {}),
        ('uk=5,de=3,jp=2', {'uk': 5, 'de': 3, 'jp': 2}),
      )

      for test_value, expected_value in test_entries:
        desc = get_relay_extrainfo_descriptor({keyword: test_value})
        self.assertEqual(expected_value, getattr(desc, attr))

      test_entries = (
        'uk=-4',
        'uki=4',
        'uk:4',
        'uk=4.de=3',
      )

      for entry in test_entries:
        desc_text = get_relay_extrainfo_descriptor({keyword: entry}, content = True)
        self._expect_invalid_attr(desc_text, attr)

  def test_minimal_bridge_descriptor(self):
    """
    Basic sanity check that we can parse a descriptor with minimal attributes.
    """

    desc = get_bridge_extrainfo_descriptor()

    self.assertEqual('ec2bridgereaac65a3', desc.nickname)
    self.assertEqual('1EC248422B57D9C0BD751892FE787585407479A4', desc.fingerprint)
    self.assertEqual('006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4', desc.digest())
    self.assertEqual([], desc.get_unrecognized_lines())

    # check that we don't have crypto fields
    self.assertRaises(AttributeError, getattr, desc, 'signature')

  def test_bridge_ip_versions_line(self):
    """
    Parses the 'bridge-ip-versions' line, which only appears in bridges.
    """

    desc = get_bridge_extrainfo_descriptor({'bridge-ip-versions': 'v4=16,v6=40'})
    self.assertEqual({'v4': 16, 'v6': 40}, desc.ip_versions)

    desc = get_bridge_extrainfo_descriptor({'bridge-ip-versions': ''})
    self.assertEqual({}, desc.ip_versions)

    desc_text = get_bridge_extrainfo_descriptor({'bridge-ip-versions': 'v4=24.5'}, content = True)
    self.assertRaises(ValueError, RelayExtraInfoDescriptor, desc_text, True)

  def test_bridge_ip_transports_line(self):
    """
    Parses the 'bridge-ip-transports' line, which only appears in bridges.
    """

    desc = get_bridge_extrainfo_descriptor({'bridge-ip-transports': '<OR>=16,<??>=40'})
    self.assertEqual({'<OR>': 16, '<??>': 40}, desc.ip_transports)

    desc = get_bridge_extrainfo_descriptor({'bridge-ip-transports': ''})
    self.assertEqual({}, desc.ip_transports)

    desc_text = get_bridge_extrainfo_descriptor({'bridge-ip-transports': '<OR>=24.5'}, content = True)
    self.assertRaises(ValueError, RelayExtraInfoDescriptor, desc_text, True)

  def test_transport_line(self):
    """
    Basic exercise for both a bridge and relay's transport entry.
    """

    desc = get_bridge_extrainfo_descriptor({'transport': 'obfs3'})
    self.assertEqual({'obfs3': (None, None, None)}, desc.transport)
    self.assertEqual([], desc.get_unrecognized_lines())

    desc = get_relay_extrainfo_descriptor({'transport': 'obfs2 83.212.96.201:33570'})
    self.assertEqual({'obfs2': ('83.212.96.201', 33570, [])}, desc.transport)
    self.assertEqual([], desc.get_unrecognized_lines())

    # multiple transport lines
    desc = get_bridge_extrainfo_descriptor({'transport': 'obfs3\ntransport obfs4'})
    self.assertEqual({'obfs3': (None, None, None), 'obfs4': (None, None, None)}, desc.transport)
    self.assertEqual([], desc.get_unrecognized_lines())

  def _expect_invalid_attr(self, desc_text, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to desc_text having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """

    self.assertRaises(ValueError, RelayExtraInfoDescriptor, desc_text, True)
    desc = RelayExtraInfoDescriptor(desc_text, validate = False)

    if attr:
      # check that the invalid attribute matches the expected value when
      # constructed without validation

      self.assertEqual(expected_value, getattr(desc, attr))
    else:
      # check a default attribute
      self.assertEqual('ninja', desc.nickname)

    return desc
