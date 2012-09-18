"""
Integration tests for stem.descriptor.networkstatus.
"""

from __future__ import with_statement

import os
import resource
import datetime
import unittest

import stem.exit_policy
import stem.version
import stem.descriptor
import stem.descriptor.networkstatus
import test.integ.descriptor

def _strptime(string):
  return datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")

class TestNetworkStatus(unittest.TestCase):
  def test_cached_consensus(self):
    """
    Parses the cached-consensus file in our data directory.
    """
    
    # lengthy test and uneffected by targets, so only run once
    if test.runner.only_run_once(self, "test_cached_consensus"): return
    
    descriptor_path = test.runner.get_runner().get_test_dir("cached-consensus")
    
    if not os.path.exists(descriptor_path):
      test.runner.skip(self, "(no cached-consensus)")
    
    if stem.util.system.is_windows():
      # might hog memory and hang the system
      # and we aren't checking for memory usage in windows, so, skip.
      test.runner.skip(self, "(unavailable on windows)")
    
    count = 0
    with open(descriptor_path) as descriptor_file:
      for desc in stem.descriptor.networkstatus.parse_file(descriptor_file):
        if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > 200000:
          # if we're using > 200 MB we should fail
          self.fail()
        assert desc.nickname # check that the router has a nickname
        count += 1
        
        # check if there's any unknown flags
        for flag in desc.flags:
          if not flag in stem.descriptor.Flag:
            # TODO: this should be a special 'new capability' check later
            # rather than failing the tests
            raise ValueError("Unrecognized flag type: %s, found on relay %s (%s)" % (flag, desc.fingerprint, desc.nickname))
    
    assert count > 100 # sanity check - assuming atleast 100 relays in the Tor network
  
  def test_metrics_consensus(self):
    """
    Checks if consensus documents from Metrics are parsed properly.
    """
    
    descriptor_path = test.integ.descriptor.get_resource("metrics_consensus")
    
    with file(descriptor_path) as descriptor_file:
      descriptors = stem.descriptor.parse_file(descriptor_path, descriptor_file)
      
      router = next(descriptors)
      self.assertEquals("sumkledi", router.nickname)
      self.assertEquals("0013D22389CD50D0B784A3E4061CB31E8CE8CEB5", router.fingerprint)
      self.assertEquals("8mCr8Sl7RF4ENU4jb0FZFA/3do8", router.digest)
      self.assertEquals(_strptime("2012-07-12 04:01:55"), router.published)
      self.assertEquals("178.218.213.229", router.address)
      self.assertEquals(80, router.or_port)
      self.assertEquals(None, router.dir_port)
  
  def test_consensus(self):
    """
    Checks that consensus documents are properly parsed.
    """
    
    descriptor_path = test.integ.descriptor.get_resource("cached-consensus")
    
    descriptor_file = file(descriptor_path)
    desc = stem.descriptor.networkstatus.NetworkStatusDocument(descriptor_file.read())
    router1 = desc.routers[0]
    descriptor_file.close()
    
    self.assertEquals("3", desc.version)
    self.assertEquals(True, desc.is_consensus)
    self.assertEquals(False, desc.is_vote)
    self.assertEquals([], desc.consensus_methods)
    self.assertEquals(None, desc.published)
    self.assertEquals(12, desc.consensus_method)
    self.assertEquals(_strptime("2012-07-12 10:00:00"), desc.valid_after)
    self.assertEquals(_strptime("2012-07-12 11:00:00"), desc.fresh_until)
    self.assertEquals(_strptime("2012-07-12 13:00:00"), desc.valid_until)
    self.assertEquals(300, desc.vote_delay)
    self.assertEquals(300, desc.dist_delay)
    expected_client_versions = [stem.version.Version(version_string) for version_string in ["0.2.2.35",
      "0.2.2.36", "0.2.2.37", "0.2.3.10-alpha", "0.2.3.11-alpha", "0.2.3.12-alpha",
      "0.2.3.13-alpha", "0.2.3.14-alpha", "0.2.3.15-alpha", "0.2.3.16-alpha", "0.2.3.17-beta",
      "0.2.3.18-rc", "0.2.3.19-rc"]]
    expected_server_versions = [stem.version.Version(version_string) for version_string in ["0.2.2.35",
      "0.2.2.36", "0.2.2.37", "0.2.3.10-alpha", "0.2.3.11-alpha", "0.2.3.12-alpha",
      "0.2.3.13-alpha", "0.2.3.14-alpha", "0.2.3.15-alpha", "0.2.3.16-alpha", "0.2.3.17-beta",
      "0.2.3.18-rc", "0.2.3.19-rc"]]
    self.assertEquals(expected_client_versions, desc.client_versions)
    self.assertEquals(expected_server_versions, desc.server_versions)
    self.assertEquals(set(desc.known_flags), set(["Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "Named", "Running", "Stable", "Unnamed", "V2Dir", "Valid"]))
    expected_params = {"CircuitPriorityHalflifeMsec": 30000, "bwauthpid": 1}
    self.assertEquals(expected_params, desc.params)
    
    self.assertEquals("sumkledi", router1.nickname)
    self.assertEquals("0013D22389CD50D0B784A3E4061CB31E8CE8CEB5", router1.fingerprint)
    self.assertEquals("8mCr8Sl7RF4ENU4jb0FZFA/3do8", router1.digest)
    self.assertEquals(_strptime("2012-07-12 04:01:55"), router1.published)
    self.assertEquals("178.218.213.229", router1.address)
    self.assertEquals(80, router1.or_port)
    self.assertEquals(None, router1.dir_port)
    self.assertEquals(set(["Exit", "Fast", "Named", "Running", "Valid"]), set(router1.flags))
    
    self.assertEquals(8, len(desc.directory_authorities))
    self.assertEquals("tor26", desc.directory_authorities[0].nickname)
    self.assertEquals("14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4", desc.directory_authorities[0].fingerprint)
    self.assertEquals("86.59.21.38", desc.directory_authorities[0].address)
    self.assertEquals("86.59.21.38", desc.directory_authorities[0].ip)
    self.assertEquals(80, desc.directory_authorities[0].dir_port)
    self.assertEquals(443, desc.directory_authorities[0].or_port)
    self.assertEquals("Peter Palfrader", desc.directory_authorities[0].contact)
    self.assertEquals(None, desc.directory_authorities[0].legacy_dir_key)
    self.assertEquals(None, desc.directory_authorities[0].key_certificate)
    self.assertEquals("0B6D1E9A300B895AA2D0B427F92917B6995C3C1C", desc.directory_authorities[0].vote_digest)
    expected_bandwidth_weights = {
        "Wbd": 3335, "Wbe": 0, "Wbg": 3536, "Wbm": 10000, "Wdb": 10000, "Web": 10000,
        "Wed": 3329, "Wee": 10000, "Weg": 3329, "Wem": 10000, "Wgb": 10000, "Wgd": 3335,
        "Wgg": 6464, "Wgm": 6464, "Wmb": 10000, "Wmd": 3335, "Wme": 0, "Wmg": 3536, "Wmm": 10000
        }
    self.assertEquals(expected_bandwidth_weights, desc.bandwidth_weights)
    
    expected_signature = """-----BEGIN SIGNATURE-----
HFXB4497LzESysYJ/4jJY83E5vLjhv+igIxD9LU6lf6ftkGeF+lNmIAIEKaMts8H
mfWcW0b+jsrXcJoCxV5IrwCDF3u1aC3diwZY6yiG186pwWbOwE41188XI2DeYPwE
I/TJmV928na7RLZe2mGHCAW3VQOvV+QkCfj05VZ8CsY=
-----END SIGNATURE-----"""
    self.assertEquals(8, len(desc.signatures))
    self.assertEquals("14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4", desc.signatures[0].identity)
    self.assertEquals("BF112F1C6D5543CFD0A32215ACABD4197B5279AD", desc.signatures[0].key_digest)
    self.assertEquals(expected_signature, desc.signatures[0].signature)
  
  def test_metrics_vote(self):
    """
    Checks if vote documents from Metrics are parsed properly.
    """
    
    descriptor_path = test.integ.descriptor.get_resource("metrics_vote")
    
    with file(descriptor_path) as descriptor_file:
      descriptors = stem.descriptor.parse_file(descriptor_path, descriptor_file)
      
      router = next(descriptors)
      self.assertEquals("sumkledi", router.nickname)
      self.assertEquals("0013D22389CD50D0B784A3E4061CB31E8CE8CEB5", router.fingerprint)
      self.assertEquals("B5n4BiALAF8B5AqafxohyYiuj7E", router.digest)
      self.assertEquals(_strptime("2012-07-11 04:22:53"), router.published)
      self.assertEquals("178.218.213.229", router.address)
      self.assertEquals(80, router.or_port)
      self.assertEquals(None, router.dir_port)
  
  def test_vote(self):
    """
    Checks that vote documents are properly parsed.
    """
    
    descriptor_path = test.integ.descriptor.get_resource("vote")
    
    descriptor_file = file(descriptor_path)
    desc = stem.descriptor.networkstatus.NetworkStatusDocument(descriptor_file.read())
    router1 = desc.routers[0]
    descriptor_file.close()
    
    self.assertEquals("3", desc.version)
    self.assertEquals(False, desc.is_consensus)
    self.assertEquals(True, desc.is_vote)
    self.assertEquals(range(1, 13), desc.consensus_methods)
    self.assertEquals(_strptime("2012-07-11 23:50:01"), desc.published)
    self.assertEquals(None, desc.consensus_method)
    self.assertEquals(_strptime("2012-07-12 00:00:00"), desc.valid_after)
    self.assertEquals(_strptime("2012-07-12 01:00:00"), desc.fresh_until)
    self.assertEquals(_strptime("2012-07-12 03:00:00"), desc.valid_until)
    self.assertEquals(300, desc.vote_delay)
    self.assertEquals(300, desc.dist_delay)
    self.assertEquals([], desc.client_versions)
    self.assertEquals([], desc.server_versions)
    self.assertEquals(set(desc.known_flags), set(["Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid"]))
    expected_params = {"CircuitPriorityHalflifeMsec": 30000, "bwauthpid": 1}
    self.assertEquals(expected_params, desc.params)
    
    self.assertEquals("sumkledi", router1.nickname)
    self.assertEquals("0013D22389CD50D0B784A3E4061CB31E8CE8CEB5", router1.fingerprint)
    self.assertEquals("B5n4BiALAF8B5AqafxohyYiuj7E", router1.digest)
    self.assertEquals(_strptime("2012-07-11 04:22:53"), router1.published)
    self.assertEquals("178.218.213.229", router1.address)
    self.assertEquals(80, router1.or_port)
    self.assertEquals(None, router1.dir_port)
    
    self.assertEquals(1, len(desc.directory_authorities))
    self.assertEquals("turtles", desc.directory_authorities[0].nickname)
    self.assertEquals("27B6B5996C426270A5C95488AA5BCEB6BCC86956", desc.directory_authorities[0].fingerprint)
    self.assertEquals("76.73.17.194", desc.directory_authorities[0].address)
    self.assertEquals("76.73.17.194", desc.directory_authorities[0].ip)
    self.assertEquals(9030, desc.directory_authorities[0].dir_port)
    self.assertEquals(9090, desc.directory_authorities[0].or_port)
    self.assertEquals("Mike Perry <email>", desc.directory_authorities[0].contact)
    self.assertEquals(None, desc.directory_authorities[0].legacy_dir_key)
    
    expected_identity_key = """-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEA6uSmsoxj2MiJ3qyZq0qYXlRoG8o82SNqg+22m+t1c7MlQOZWPJYn
XeMcBCt8xrTeIt2ZI+Q/Kt2QJSeD9WZRevTKk/kn5Tg2+xXPogalUU47y5tUohGz
+Q8+CxtRSXpDxBHL2P8rLHvGrI69wbNHGoQkce/7gJy9vw5Ie2qzbyXk1NG6V8Fb
pr6A885vHo6TbhUnolz2Wqt/kN+UorjLkN2H3fV+iGcQFv42SyHYGDLa0WwL3PJJ
r/veu36S3VaHBrfhutfioi+d3d4Ya0bKwiWi5Lm2CHuuRTgMpHLU9vlci8Hunuxq
HsULe2oMsr4VEic7sW5SPC5Obpx6hStHdNv1GxoSEm3/vIuPM8pINpU5ZYAyH9yO
Ef22ZHeiVMMKmpV9TtFyiFqvlI6GpQn3mNbsQqF1y3XCA3Q4vlRAkpgJVUSvTxFP
2bNDobOyVCpCM/rwxU1+RCNY5MFJ/+oktUY+0ydvTen3gFdZdgNqCYjKPLfBNm9m
RGL7jZunMUNvAgMBAAE=
-----END RSA PUBLIC KEY-----"""
    expected_signing_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJ5itcJRYNEM3Qf1OVWLRkwjqf84oXPc2ZusaJ5zOe7TVvBMra9GNyc0
NM9y6zVkHCAePAjr4KbW/8P1olA6FUE2LV9bozaU1jFf6K8B2OELKs5FUEW+n+ic
GM0x6MhngyXonWOcKt5Gj+mAu5lrno9tpNbPkz2Utr/Pi0nsDhWlAgMBAAE=
-----END RSA PUBLIC KEY-----"""
    expected_key_crosscert = """-----BEGIN ID SIGNATURE-----
RHYImGTwg36wmEdAn7qaRg2sAfql7ZCtPIL/O3lU5OIdXXp0tNn/K00Bamqohjk+
Tz4FKsKXGDlbGv67PQcZPOK6NF0GRkNh4pk89prrDO4XwtEn7rkHHdBH6/qQ7IRG
GdDZHtZ1a69oFZvPWD3hUaB50xeIe7GoKdKIfdNNJ+8=
-----END ID SIGNATURE-----"""
    expected_key_certification = """-----BEGIN SIGNATURE-----
fasWOGyUZ3iMCYpDfJ+0JcMiTH25sXPWzvlHorEOyOMbaMqRYpZU4GHzt1jLgdl6
AAoR6KdamsLg5VE8xzst48a4UFuzHFlklZ5O8om2rcvDd5DhSnWWYZnYJecqB+bo
dNisPmaIVSAWb29U8BpNRj4GMC9KAgGYUj8aE/KtutAeEekFfFEHTfWZ2fFp4j3m
9rY8FWraqyiF+Emq1T8pAAgMQ+79R3oZxq0TXS42Z4Anhms735ccauKhI3pDKjbl
tD5vAzIHOyjAOXj7a6jY/GrnaBNuJ4qe/4Hf9UmzK/jKKwG95BPJtPTT4LoFwEB0
KG2OUeQUNoCck4nDpsZwFqPlrWCHcHfTV2iDYFV1HQWDTtZz/qf+GtB8NXsq+I1w
brADmvReM2BD6p/13h0QURCI5hq7ZYlIKcKrBa0jn1d9cduULl7vgKsRCJDls/ID
emBZ6pUxMpBmV0v+PrA3v9w4DlE7GHAq61FF/zju2kpqj6MInbEvI/E+e438sWsL
-----END SIGNATURE-----"""
    self.assertEquals("3", desc.directory_authorities[0].key_certificate.key_certificate_version)
    self.assertEquals("27B6B5996C426270A5C95488AA5BCEB6BCC86956", desc.directory_authorities[0].key_certificate.fingerprint)
    self.assertEquals(_strptime("2011-11-28 21:51:04"), desc.directory_authorities[0].key_certificate.published)
    self.assertEquals(_strptime("2012-11-28 21:51:04"), desc.directory_authorities[0].key_certificate.expires)
    self.assertEquals(expected_identity_key, desc.directory_authorities[0].key_certificate.identity_key)
    self.assertEquals(expected_signing_key, desc.directory_authorities[0].key_certificate.signing_key)
    self.assertEquals(expected_key_crosscert, desc.directory_authorities[0].key_certificate.crosscert)
    self.assertEquals(expected_key_certification, desc.directory_authorities[0].key_certificate.certification)
    self.assertEquals(None, desc.directory_authorities[0].vote_digest)
    self.assertEquals({}, desc.bandwidth_weights)
    
    expected_signature = """-----BEGIN SIGNATURE-----
fskXN84wB3mXfo+yKGSt0AcDaaPuU3NwMR3ROxWgLN0KjAaVi2eV9PkPCsQkcgw3
JZ/1HL9sHyZfo6bwaC6YSM9PNiiY6L7rnGpS7UkHiFI+M96VCMorvjm5YPs3FioJ
DnN5aFtYKiTc19qIC7Nmo+afPdDEf0MlJvEOP5EWl3w=
-----END SIGNATURE-----"""
    self.assertEquals(1, len(desc.signatures))
    self.assertEquals("27B6B5996C426270A5C95488AA5BCEB6BCC86956", desc.signatures[0].identity)
    self.assertEquals("D5C30C15BB3F1DA27669C2D88439939E8F418FCF", desc.signatures[0].key_digest)
    self.assertEquals(expected_signature, desc.signatures[0].signature)
  
  def test_cached_microdesc_consensus(self):
    """
    Parses the cached-microdesc-consensus file in our data directory.
    """
    
    # lengthy test and uneffected by targets, so only run once
    if test.runner.only_run_once(self, "test_cached_microdesc_consensus"): return
    
    descriptor_path = test.runner.get_runner().get_test_dir("cached-microdesc-consensus")
    
    if not os.path.exists(descriptor_path):
      test.runner.skip(self, "(no cached-microdesc-consensus)")
    
    count = 0
    with open(descriptor_path) as descriptor_file:
      for desc in stem.descriptor.networkstatus.parse_file(descriptor_file, True, is_microdescriptor = True):
        assert desc.nickname # check that the router has a nickname
        count += 1
    
    assert count > 100 # sanity check - assuming atleast 100 relays in the consensus

