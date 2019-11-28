Tortoise and the Hare
=====================

Controllers have two methods of talking with Tor...

* **Synchronous** - Most commonly you make a request to Tor then receive its
  reply. The :func:`~stem.control.Controller.get_info` calls in the `first
  tutorial <the_little_relay_that_could.html>`_ are an example of this.

* **Asynchronous** - Controllers can subscribe to be notified when various
  kinds of events occur within Tor (see the :data:`~stem.control.EventType`).
  Stem's users provide a callback function to
  :func:`~stem.control.Controller.add_event_listener` which is then notified
  when the event occurs.

Try to avoid lengthy operations within event callbacks. They're notified by a
single dedicated event thread, and blocking this thread will prevent the
delivery of further events.

With that out of the way lets see an example. The following is a `curses
<https://docs.python.org/2/howto/curses.html>`_ application that graphs the
bandwidth usage of Tor...

.. image:: /_static/bandwidth_graph_output.png

To do this it listens to **BW events**
(the class for which is a :class:`~stem.response.events.BandwidthEvent`). These
are events that Tor emits each second saying the number of bytes downloaded and
uploaded.

.. literalinclude:: /_static/example/event_listening.py
   :emphasize-lines: 53-55,62-67
   :language: python

Advanced Listeners
------------------

When you attach a listener to a :class:`~stem.control.Controller` events are
processed within a dedicated thread. This is convenient for simple uses, but
can make troubleshooting your code confusing. For example, exceptions have
nowhere to propagate...

.. literalinclude:: /_static/example/broken_listener.py
   :language: python

::

  % python demo.py 
  start of broken_handler
  start of broken_handler
  start of broken_handler

... and processing events slower than they're received will make your listener
fall behind. This can result in a memory leak for long running processes...

.. literalinclude:: /_static/example/slow_listener.py
   :language: python

::

  % python demo.py 
  processing a BW event that's 0.9 seconds old (0 more events are waiting)
  processing a BW event that's 4.9 seconds old (3 more events are waiting)
  processing a BW event that's 8.9 seconds old (7 more events are waiting)

Avoid performing heavy business logic directly within listeners. For example, a
producer/consumer pattern sidesteps these issues...

.. literalinclude:: /_static/example/queue_listener.py
   :language: python

::

  % python demo.py 
  I got a BW event for 20634 bytes downloaded and 2686 bytes uploaded
  I got a BW event for 0 bytes downloaded and 0 bytes uploaded
  I got a BW event for 0 bytes downloaded and 0 bytes uploaded
