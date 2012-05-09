"""
Integration tests for stem.descriptor.extrainfo_descriptor.
"""

import os
import datetime
import unittest

import stem.descriptor.extrainfo_descriptor
import test.runner
import test.integ.descriptor

# 'test_cached_descriptor' is a lengthy test and uneffected by testing targets,
# so including a flag to prevent it from being ran multiple times

RAN_CACHED_DESCRIPTOR_TEST = False

class TestExtraInfoDescriptor(unittest.TestCase):
  is_cached_descriptors_available = None
  
  def setUp(self):
    if self.is_cached_descriptors_available is None:
      descriptor_path = test.runner.get_runner().get_test_dir("cached-extrainfo")
      self.is_cached_descriptors_available = os.path.exists(descriptor_path)
  
  def test_metrics_descriptor(self):
    """
    Parses and checks our results against an extrainfo descriptor from metrics.
    """
    
    descriptor_path = test.integ.descriptor.get_resource("extrainfo_descriptor")
    
    descriptor_file = open(descriptor_path)
    descriptor_contents = descriptor_file.read()
    descriptor_file.close()
    
    expected_signature = """-----BEGIN SIGNATURE-----
K5FSywk7qvw/boA4DQcqkls6Ize5vcBYfhQ8JnOeRQC9+uDxbnpm3qaYN9jZ8myj
k0d2aofcVbHr4fPQOSST0LXDrhFl5Fqo5um296zpJGvRUeO6S44U/EfJAGShtqWw
7LZqklu+gVvhMKREpchVqlAwXkWR44VENm24Hs+mT3M=
-----END SIGNATURE-----"""
    
    desc = stem.descriptor.extrainfo_descriptor.ExtraInfoDescriptor(descriptor_contents)
    self.assertEquals("NINJA", desc.nickname)
    self.assertEquals("B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48", desc.fingerprint)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 3, 50), desc.published)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.read_history_end)
    self.assertEquals(900, desc.read_history_interval)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.write_history_end)
    self.assertEquals(900, desc.write_history_interval)
    self.assertEquals(expected_signature, desc.signature)
    
    # TODO: still missing dirreq-read-history and dirreq-write-history
    #self.assertEquals([], desc.get_unrecognized_lines())
    
    # The read-history and write-history lines are pretty long so just checking
    # the initial contents for the line and parsed values.
    
    read_start = "2012-05-05 17:02:45 (900 s) 3309568,9216,41984"
    self.assertTrue(desc.read_history.startswith(read_start))
    
    read_values_start = [3309568, 9216, 41984, 27648, 123904]
    self.assertEquals(read_values_start, desc.read_history_values[:5])
    
    write_start = "2012-05-05 17:02:45 (900 s) 1082368,19456,50176,272384"
    self.assertTrue(desc.write_history.startswith(write_start))
    
    write_values_start = [1082368, 19456, 50176, 272384, 485376]
    self.assertEquals(write_values_start, desc.write_history_values[:5])
  
  def test_cached_descriptor(self):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """
    
    descriptor_path = test.runner.get_runner().get_test_dir("cached-extrainfo")
    
    if not self.is_cached_descriptors_available:
      self.skipTest("(no cached descriptors)")
    
    global RAN_CACHED_DESCRIPTOR_TEST
    
    if RAN_CACHED_DESCRIPTOR_TEST:
      self.skipTest("(already ran)")
    else:
      RAN_CACHED_DESCRIPTOR_TEST = True
    
    with open(descriptor_path) as descriptor_file:
      for desc in stem.descriptor.extrainfo_descriptor.parse_file(descriptor_file):
        # TODO: uncomment when we're done implementing the ExtraInfoDescriptor class
        #unrecognized_lines = desc.get_unrecognized_lines()
        unrecognized_lines = []
        
        if unrecognized_lines:
          # TODO: This isn't actually a problem, and rather than failing we
          # should alert the user about these entries at the end of the tests
          # (along with new events, getinfo options, and such). For now though
          # there doesn't seem to be anything in practice to trigger this so
          # failing to get our attention if it does.
          
          print "Unrecognized descriptor content: %s" % unrecognized_lines
          self.fail()

