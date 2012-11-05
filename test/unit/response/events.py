"""
Unit tests for the stem.response.events classes.
"""

import threading
import unittest

import stem.response
import stem.response.events
import test.mocking as mocking

from stem.socket import ProtocolError

def _get_event(content):
  controller_event = mocking.get_message(content)
  stem.response.convert("EVENT", controller_event, arrived_at = 25)
  return controller_event

class TestEvents(unittest.TestCase):
  def test_example(self):
    """
    Exercises the add_event_listener() pydoc example, but without the sleep().
    """
    
    import time
    from stem.control import Controller, EventType
    
    def print_bw(event):
      msg = "sent: %i, received: %i" % (event.written, event.read)
      self.assertEqual("sent: 25, received: 15", msg)
    
    def event_sender():
      for i in xrange(3):
        print_bw(_get_event("650 BW 15 25"))
        time.sleep(0.05)
    
    controller = mocking.get_object(Controller, {
      'authenticate': mocking.no_op(),
      'add_event_listener': mocking.no_op(),
    })
    
    controller.authenticate()
    controller.add_event_listener(print_bw, EventType.BW)
    
    events_thread = threading.Thread(target = event_sender)
    events_thread.start()
    time.sleep(0.2)
    events_thread.join()
  
  def test_bw_event(self):
    event = _get_event("650 BW 15 25")
    
    self.assertTrue(isinstance(event, stem.response.events.BandwidthEvent))
    self.assertEqual(15, event.read)
    self.assertEqual(25, event.written)
    
    event = _get_event("650 BW 0 0")
    self.assertEqual(0, event.read)
    self.assertEqual(0, event.written)
    
    # BW events are documented as possibly having various keywords including
    # DIR, OR, EXIT, and APP in the future. This is kinda a pointless note
    # since tor doesn't actually do it yet (and likely never will), but might
    # as well sanity test that it'll be ok.
    
    event = _get_event("650 BW 10 20 OR=5 EXIT=500")
    self.assertEqual(10, event.read)
    self.assertEqual(20, event.written)
    self.assertEqual({'OR': '5', 'EXIT': '500'}, event.keyword_args)
    
    self.assertRaises(ProtocolError, _get_event, "650 BW 15")
    self.assertRaises(ProtocolError, _get_event, "650 BW -15 25")
    self.assertRaises(ProtocolError, _get_event, "650 BW 15 -25")
    self.assertRaises(ProtocolError, _get_event, "650 BW x 25")

