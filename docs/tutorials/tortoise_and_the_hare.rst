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

