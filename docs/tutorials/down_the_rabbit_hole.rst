Down the Rabbit Hole
====================

Underneath it all Stem is a Python implementation of Tor's `control
<https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_ and
`directory specifications
<https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_.
Anything you can do with Stem you can also do `with telnet
<../faq.html#can-i-interact-with-tors-controller-interface-directly>`_ (albeit
with quite a bit of extra work).

Playing with Tor's control port directly is a great way of learning what
Tor can and cannot do. This is handy because Stem can take advantage of
anything the control interface offers, but conversely is also limited by
things it lacks.

To help Stem offers a control prompt with nice usability improvements over
telnet...

* Irc-style commands like '**/help**'.
* Is a **python interpreter** (like IDLE).
* Tab completion for Tor's controller commands.
* History scrollback by pressing up/down.
* Transparently handles Tor authentication at startup.
* Colorized output for improved readability.

.. _getting-started:

Getting started
---------------

Getting started with the control prompt is easy. Assuming you have Stem
installed it will be available under **/usr/local/bin/tor-prompt**, and can
attach to either an existing Tor instance or start one of its own.

If Tor's already running `with a control port
<the_little_relay_that_could.html>`_ then you can attach to it using
**--interface** or **--socket** (by default it checks on **port 9051**)...

.. image:: /_static/prompt/attach.png

If Tor isn't running this prompt will start a temporary instance of its own.
Tor will have a minimal non-relaying configuration, and be shut down when
you're done.

.. image:: /_static/prompt/starting_tor.png

.. _what-can-i-do-with-it:

What can I do with it?
----------------------

This prompt accepts three types of commands...

* Commands for the interpreter itself, such as **/help** and **/info**. These
  are handled by the interpreter and always begin with a slash.

* Commands for Tor's control port, such as **GETINFO version** and **GETCONF
  ExitPolicy**. These are passed along directly to Tor.

* Commands that do not match either of the above are treated as Python.

To get a list of the interpreter and Tor commands run **/help**. You can also
run **/help [command]** (such as **/help SIGNAL**) to get details on what
does...

.. image:: /_static/prompt/help.png

Another useful interpreter command is **/info [relay]** which provides
information about a relay. With this you can look up details about any relay by
its IP address, fingerprint, or nickname...

.. image:: /_static/prompt/info.png

Tor commands are passed along directly to Tor's control port, providing raw
responses just as telnet would...

.. image:: /_static/prompt/tor_commands.png

And last but certainly not least this prompt provides a Python interpreter,
just like IDLE. You start with a :class:`~stem.control.Controller` for you Tor
instance available as your **controller** variable. This makes it easy to
experiment with Stem and see what it can do...

.. image:: /_static/prompt/python.png

.. _event-handling:

Event handling
--------------

As mentioned in an `earlier tutorial <tortoise_and_the_hare.html>`_ you can
subscribe to receive events from Tor. Stem's :class:`~stem.control.Controller`
does this with its :func:`~stem.control.Controller.add_event_listener` method,
but with our raw Tor access we can also subscribe with **SETEVENTS [event
types]**.

Events we've received are available in two different ways. First, **/events**
provides a quick dump of the events we've received thus far...

.. image:: /_static/prompt/events_command.png

You can list events of just a certain type by saying which (for instance
**/events BW**). More useful though is the **events()** function, which
provides a list of :class:`~stem.response.events.Event` instances we've
received...

.. image:: /_static/prompt/events_variable.png

You can specify event types to either **/events** or **events()** to just
receive events of those types (for instance, **events('BW', 'DEBUG')**).

To stop receiving events run **SETEVENTS** without any event types, and to
clear the backlog of events we've received run **/events clear**.

