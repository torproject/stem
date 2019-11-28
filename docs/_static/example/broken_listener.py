import time

from stem.control import EventType, Controller


def broken_handler(event):
  print('start of broken_handler')
  raise ValueError('boom')
  print('end of broken_handler')


with Controller.from_port() as controller:
  controller.authenticate()
  controller.add_event_listener(broken_handler, EventType.BW)
  time.sleep(2)
