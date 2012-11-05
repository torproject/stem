"""
Unit tests for the stem.response.events classes.
"""

import threading
import unittest

import stem.response
import test.mocking as mocking

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
        controller_event = mocking.get_message("650 BW 15 25")
        stem.response.convert("EVENT", controller_event, arrived_at = 25)
        print_bw(controller_event)
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

