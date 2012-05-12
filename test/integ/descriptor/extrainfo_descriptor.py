"""
Integration tests for stem.descriptor.extrainfo_descriptor.
"""

import os
import datetime
import unittest

import stem.descriptor.extrainfo_descriptor
import test.runner
import test.integ.descriptor

RAN_CACHED_DESCRIPTOR_TEST = False

class TestExtraInfoDescriptor(unittest.TestCase):
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
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.dir_read_history_end)
    self.assertEquals(900, desc.dir_read_history_interval)
    self.assertEquals(datetime.datetime(2012, 5, 5, 17, 2, 45), desc.dir_write_history_end)
    self.assertEquals(900, desc.dir_write_history_interval)
    self.assertEquals(expected_signature, desc.signature)
    self.assertEquals([], desc.get_unrecognized_lines())
    
    # The read-history, write-history, dirreq-read-history, and
    # dirreq-write-history lines are pretty long so just checking
    # the initial contents for the line and parsed values.
    
    read_values_start = [3309568, 9216, 41984, 27648, 123904]
    self.assertEquals(read_values_start, desc.read_history_values[:5])
    
    write_values_start = [1082368, 19456, 50176, 272384, 485376]
    self.assertEquals(write_values_start, desc.write_history_values[:5])
    
    dir_read_values_start = [0, 0, 0, 0, 33792, 27648, 48128]
    self.assertEquals(dir_read_values_start, desc.dir_read_history_values[:7])
    
    dir_write_values_start = [0, 0, 0, 227328, 349184, 382976, 738304]
    self.assertEquals(dir_write_values_start, desc.dir_write_history_values[:7])
  
  def test_cached_descriptor(self):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """
    
    global RAN_CACHED_DESCRIPTOR_TEST
    descriptor_path = test.runner.get_runner().get_test_dir("cached-extrainfo")
    
    if RAN_CACHED_DESCRIPTOR_TEST:
      self.skipTest("(already ran)")
    elif not os.path.exists(descriptor_path):
      self.skipTest("(no cached descriptors)")
    
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

