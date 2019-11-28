import queue
import time

from stem.control import EventType, Controller


with Controller.from_port() as controller:
  controller.authenticate()

  start_time = time.time()
  event_queue = queue.Queue()

  controller.add_event_listener(lambda event: event_queue.put(event), EventType.BW)

  while time.time() - start_time < 2:
    event = event_queue.get()
    print('I got a BW event for %i bytes downloaded and %i bytes uploaded' % (event.read, event.written))
