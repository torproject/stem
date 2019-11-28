import time

from stem.control import EventType, Controller


with Controller.from_port() as controller:
  def slow_handler(event):
    age = time.time() - event.arrived_at
    unprocessed_count = controller._event_queue.qsize()

    print("processing a BW event that's %0.1f seconds old (%i more events are waiting)" % (age, unprocessed_count))
    time.sleep(5)

  controller.authenticate()
  controller.add_event_listener(slow_handler, EventType.BW)
  time.sleep(10)
