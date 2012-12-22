"""
Tests for the examples given in stem's tutorial.
"""

from __future__ import with_statement

import unittest

from test import mocking

class TestTutorial(unittest.TestCase):
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_the_little_relay_that_could(self):
    from stem.control import Controller
    
    controller = mocking.get_object(Controller, {
      'authenticate': mocking.no_op(),
      'close': mocking.no_op(),
      'get_info': mocking.return_for_args({
        ('traffic/read',): '1234',
        ('traffic/written',): '5678',
      }),
    })
    
    controller.authenticate()
    
    bytes_read = controller.get_info("traffic/read")
    bytes_written = controller.get_info("traffic/written")
    
    expected_line = "My Tor relay has read 1234 bytes and written 5678."
    printed_line = "My Tor relay has read %s bytes and written %s." % (bytes_read, bytes_written)
    self.assertEqual(expected_line, printed_line)
    
    controller.close()
  
  def test_mirror_mirror_on_the_wall(self):
    from stem.descriptor.server_descriptor import RelayDescriptor
    from stem.descriptor.reader import DescriptorReader
    from stem.util import str_tools
    
    exit_descriptor = mocking.get_relay_server_descriptor({
     'router': 'speedyexit 149.255.97.109 9001 0 0'
    }, content = True).replace('reject *:*', 'accept *:*')
    exit_descriptor = mocking.sign_descriptor_content(exit_descriptor)
    exit_descriptor = RelayDescriptor(exit_descriptor)
    
    reader_wrapper = mocking.get_object(DescriptorReader, {
      '__enter__': lambda x: x,
      '__exit__': mocking.no_op(),
      '__iter__': mocking.return_value(iter((
        exit_descriptor,
        mocking.get_relay_server_descriptor(), # non-exit
        exit_descriptor,
        exit_descriptor,
      )))
    })
    
    # provides a mapping of observed bandwidth to the relay nicknames
    def get_bw_to_relay():
      bw_to_relay = {}
      
      with reader_wrapper as reader:
        for desc in reader:
          if desc.exit_policy.is_exiting_allowed():
            bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
      
      return bw_to_relay
    
    # prints the top fifteen relays
    
    bw_to_relay = get_bw_to_relay()
    count = 1
    
    for bw_value in sorted(bw_to_relay.keys(), reverse = True):
      for nickname in bw_to_relay[bw_value]:
        expected_line = "%i. speedyexit (102.13 KB/s)" % count
        printed_line = "%i. %s (%s/s)" % (count, nickname, str_tools.get_size_label(bw_value, 2))
        self.assertEqual(expected_line, printed_line)
        
        count += 1
        
        if count > 15:
          return
    
    self.assertEqual(4, count)

