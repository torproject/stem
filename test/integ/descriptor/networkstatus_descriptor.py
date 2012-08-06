"""
Integration tests for stem.descriptor.server_descriptor.
"""

from __future__ import with_statement

import datetime
import unittest

import stem.exit_policy
import stem.version
import stem.descriptor.networkstatus_descriptor
import test.integ.descriptor

def _strptime(string):
  return datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")

class TestNetworkStatusDocument(unittest.TestCase):
  def test_metrics_consensus(self):
    """
    Checks if consensus documents from Metrics are parsed properly.
    """
    
    descriptor_path = test.integ.descriptor.get_resource("metrics_consensus")
    
    with file(descriptor_path) as descriptor_file:
      desc = stem.descriptor.parse_file(descriptor_path, descriptor_file)
      
      router = next(desc)
      self.assertEquals("sumkledi", router.nickname)
      self.assertEquals("ABPSI4nNUNC3hKPkBhyzHozozrU", router.identity)
      self.assertEquals("8mCr8Sl7RF4ENU4jb0FZFA/3do8", router.digest)
      self.assertEquals(_strptime("2012-07-12 04:01:55"), router.publication)
      self.assertEquals("178.218.213.229", router.ip)
      self.assertEquals(80, router.orport)
      self.assertEquals(None, router.dirport)
