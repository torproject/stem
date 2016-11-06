Frequently Asked Questions
==========================

* **General Information**

 * :ref:`what_is_stem`
 * :ref:`does_stem_have_any_dependencies`
 * :ref:`what_python_versions_is_stem_compatible_with`
 * :ref:`can_i_interact_with_tors_controller_interface_directly`
 * :ref:`are_there_any_other_controller_libraries`
 * :ref:`what_license_is_stem_under`
 * :ref:`where_can_i_get_help`

* **Usage**

 * :ref:`how_do_i_connect_to_tor`
 * :ref:`how_do_i_request_a_new_identity_from_tor`
 * :ref:`how_do_i_reload_my_torrc`
 * :ref:`how_do_i_read_tar_xz_descriptor_archives`
 * :ref:`what_is_that_with_keyword_i_keep_seeing_in_the_tutorials`

* **Development**

 * :ref:`how_do_i_get_started`
 * :ref:`how_do_i_run_the_tests`
 * :ref:`how_do_i_test_compatibility_with_multiple_python_versions`
 * :ref:`how_do_i_build_the_site`
 * :ref:`what_is_the_copyright_for_patches`

General Information
===================

.. _what_is_stem:

What is Stem?
-------------

Stem is a Python controller library that you can use to interact with `Tor
<https://www.torproject.org/>`_. With it you can write scripts and applications
with capabilities similar `arm <https://www.atagar.com/arm/>`_.

From a technical standpoint, Stem is a Python implementation of Tor's
`directory <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_ and
`control specifications
<https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_. `To get
started see our tutorials! <tutorials.html>`_

.. _does_stem_have_any_dependencies:

Does Stem have any dependencies?
--------------------------------

**No.** All you need in order to use Stem is Python.

When it is available Stem will use `pycrypto
<https://www.dlitz.net/software/pycrypto/>`_ to validate descriptor signatures.
However, there is no need to install pycrypto unless you need this
functionality.

.. _what_python_versions_is_stem_compatible_with:

What Python versions is Stem compatible with?
---------------------------------------------

Stem works with **Python 2.6 and greater**, including the Python 3.x series.

.. _can_i_interact_with_tors_controller_interface_directly:

Can I interact with Tor's controller interface directly?
--------------------------------------------------------

Yup. You don't need a library to interact with Tor's `controller interface
<https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_, and
interacting with it directly is a great way to learn about what it can do. The
exact details for how you connect to Tor depend on two things...

* Where is Tor listening for controller connections? This is specified by
  either the **ControlPort** or **ControlSocket** option in your torrc. If you
  have neither then Tor will not accept controller connections.

* What type of authentication is Tor's controller interface using? This is
  defined by your **CookieAuthentication** or **HashedControlPassword** option.
  If you have neither then Tor does not restrict access.

We'll tackle each of these scenarios one at a time...

**I'm using a ControlPort**
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are using a **ControlPort** then the easiest method of talking with Tor
is via **telnet**. You always need to authenticate after connecting, even if
Tor does not restrict access. If your torrc doesn't have a
**CookieAuthentication** or **HashedControlPassword** then to authenticate you
will simply call **AUTHENTICATE** after connecting without any credentials.

::

  % cat ~/.tor/torrc
  ControlPort 9051

  % telnet localhost 9051
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  AUTHENTICATE
  250 OK
  GETINFO version
  250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)
  250 OK
  QUIT
  250 closing connection
  Connection closed by foreign host.

**I'm using a ControlSocket**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A **ControlSocket** is a file based socket, so we'll use **socat** to connect
to it...

::

  % cat ~/.tor/torrc
  ControlSocket /home/atagar/.tor/socket

  % socat UNIX-CONNECT:/home/atagar/.tor/socket STDIN
  AUTHENTICATE
  250 OK
  GETINFO version
  250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)
  250 OK
  QUIT
  250 closing connection

**I'm using cookie authentication**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cookie authentication simply means that your credential is the content of a
file in Tor's **DataDirectory**. You can learn information about Tor's method
of authentication (including the cookie file's location) by calling
**PROTOCOLINFO**...

::

  % cat ~/.tor/torrc
  ControlPort 9051
  CookieAuthentication 1

  % telnet localhost 9051
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  PROTOCOLINFO
  250-PROTOCOLINFO 1
  250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/home/atagar/.tor/control_auth_cookie"
  250-VERSION Tor="0.2.5.1-alpha-dev"
  250 OK

Cookie authentication has two flavors: **COOKIE** and **SAFECOOKIE**. Below
we'll show you how to authenticate via COOKIE. SAFECOOKIE authentication is a
lot more involved, and not something you will want to do by hand (though Stem
supports it transparently).

To get the credential for your AUTHENTICATE command we will use **hexdump**...

::

  % hexdump -e '32/1 "%02x""\n"' /home/atagar/.tor/control_auth_cookie
  be9c9e18364e33d5eb8ba820d456aa2bc03444c0420f089ba4569b6aeecc6254

  % telnet localhost 9051
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  AUTHENTICATE be9c9e18364e33d5eb8ba820d456aa2bc03444c0420f089ba4569b6aeecc6254
  250 OK
  GETINFO version
  250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)
  250 OK
  QUIT
  250 closing connection
  Connection closed by foreign host.

**I'm using password authentication**
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tor's other method of authentication is a credential you know. To use it ask
Tor to hash your password, then use that in your torrc...

::

  % tor --hash-password "my_password"
  16:E600ADC1B52C80BB6022A0E999A7734571A451EB6AE50FED489B72E3DF

Authenticating with this simply involves giving Tor the credential...

::

  % cat ~/.tor/torrc
  ControlPort 9051
  HashedControlPassword 16:E600ADC1B52C80BB6022A0E999A7734571A451EB6AE50FED489B72E3DF

  % telnet localhost 9051
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  AUTHENTICATE "my_password"
  250 OK
  GETINFO version
  250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)
  250 OK
  QUIT
  250 closing connection
  Connection closed by foreign host.

.. _are_there_any_other_controller_libraries:

Are there any other controller libraries?
-----------------------------------------

Yup. The most mature controller libraries are written in Python, but there's a
few options in other languages as well. By far the most mature alternative to
Stem are `Txtorcon <https://txtorcon.readthedocs.org/>`_ and `TorCtl
<https://gitweb.torproject.org/pytorctl.git>`_.

`Txtorcon <https://txtorcon.readthedocs.org/>`_ is an actively maintained
controller library written by Meejah for `Twisted
<https://twistedmatrix.com/trac/>`_. In the future we plan to `integrate Stem
and Txtorcon
<https://www.torproject.org/getinvolved/volunteer.html.en#txtorcon-stemIntegration>`_
to some degree, but that is still a ways off.

`TorCtl <https://gitweb.torproject.org/pytorctl.git>`_ was Stem's predecessor
and `deprecated in December 2012
<https://blog.torproject.org/blog/torctl-deprecation-and-stem-plans>`_ in favor
of Stem. Though no longer actively developed, it's still quite functional and
still used for several `TorFlow <https://gitweb.torproject.org/torflow.git>`_
based projects.

The following are the functional controller libraries I'm aware of. Dates are
for highly active development. If I missed one then please `let me know
<https://www.atagar.com/contact/>`_!

==================================================================  ================    =======================
Library                                                             Language            Developed
==================================================================  ================    =======================
`Stem <https://stem.torproject.org/>`_                              Python              October 2011 - Present
`Txtorcon <https://txtorcon.readthedocs.org/>`_                     Python (Twisted)    February 2012 - Present
`TorCtl <https://gitweb.torproject.org/pytorctl.git>`_              Python              July 2008 - November 2011
`PHP TorCtl <https://github.com/dunglas/php-torcontrol/>`_          PHP                 February 2013
`JTorCtl <https://gitweb.torproject.org/jtorctl.git>`_              Java                June 2005 - May 2009
`Orc <https://github.com/sycamoreone/orc>`_                         Go                  January 2015
`Bulb <https://github.com/Yawning/bulb>`_                           Go                  March 2015
`Rust Controller <https://github.com/Dhole/rust-tor-controller>`_   Rust                May 2016
==================================================================  ================    =======================

.. _what_license_is_stem_under:

What license is Stem under?
---------------------------

Stem is under the `LGPLv3 <https://www.gnu.org/licenses/lgpl>`_.

.. _where_can_i_get_help:

Where can I get help?
---------------------

Do you have a Tor related question or project that you would like to discuss?
If so then find us on the `tor-dev@ email list
<https://lists.torproject.org/cgi-bin/mailman/listinfo/tor-dev>`_ and `IRC
<https://www.torproject.org/about/contact.html.en#irc>`_.

Usage
=====

.. _how_do_i_connect_to_tor:

How do I connect to Tor?
------------------------

Once you have Tor running and `properly configured <tutorials/the_little_relay_that_could.html>`_ you have a few ways of connecting to it. The following are the most common methods for getting a :class:`~stem.control.Controller` instance, from the highest to lowest level...

#. `Connection Module <api/connection.html>`_

   Writing a commandline script? Then the :func:`~stem.connection.connect`
   function provide you the quickest and most hassle free method for getting a
   :class:`~stem.control.Controller`.

   This function connects and authenticates to the given port or socket,
   providing you a one-line method of getting a
   :class:`~stem.control.Controller` that's ready to use. If Tor requires a
   password then the user will be prompted for it. When the connection cannot
   be established this prints a description of the problem to stdout and
   returns **None**.

#. `Control Module <api/control.html>`_

   The connection module helpers above are all well and good when you need a
   quick-and-dirty connection for your commandline script, but they're
   inflexible. In particular their lack of exceptions and direct use of
   stdin/stdout make them undesirable for more complicated situations. That's
   where the Controller's :func:`~stem.control.Controller.from_port` and
   :func:`~stem.control.Controller.from_socket_file` methods come in.

   These provide the most flexible method of connecting to Tor, and for
   sophisticated applications is what you'll want.

#. `Socket Module <api/socket.html>`_

   For the diehards among us you can skip the conveniences of a high level
   :class:`~stem.control.Controller` and work directly with the raw components.
   At Stem's lowest level your connection with Tor is a
   :class:`~stem.socket.ControlSocket` subclass. This provides methods to send,
   receive, disconnect, and reconnect to Tor.

.. _how_do_i_request_a_new_identity_from_tor:

How do I request a new identity from Tor?
-----------------------------------------

In Tor your identity is the three-hop **circuit** over which your traffic travels through the Tor network.

Tor periodically creates new circuits. When a circuit is used it becomes **dirty**, and after ten minutes new connections will not use it. When all of the connections using an expired circuit are done the circuit is closed.

An important thing to note is that a new circuit does not necessarily mean a new IP address. Paths are randomly selected based on heuristics like speed and stability. There are only so many large exits in the Tor network, so it's not uncommon to reuse an exit you have had previously.

Tor does not have a method for cycling your IP address. This is on purpose, and done for a couple reasons. The first is that this capability is usually requested for not-so-nice reasons such as ban evasion or SEO. Second, repeated circuit creation puts a very high load on the Tor network, so please don't!

With all that out of the way, how do you create a new circuit? You can customize the rate at which Tor cycles circuits with the **MaxCircuitDirtiness** option in your `torrc <https://www.torproject.org/docs/faq.html.en#torrc>`_. `Vidalia <https://en.wikipedia.org/wiki/Vidalia_%28software%29>`_ and `arm <https://www.atagar.com/arm/>`_ both provide a method to request a new identity, and you can do so programmatically by sending Tor a NEWNYM signal.

To do this with telnet...

::

  % telnet localhost 9051
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  AUTHENTICATE
  250 OK
  SIGNAL NEWNYM
  250 OK

And with Stem...

::

  from stem import Signal
  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()
    controller.signal(Signal.NEWNYM)

.. _how_do_i_reload_my_torrc:

How do I reload my torrc?
-------------------------

Tor is configured through its `torrc
<https://www.torproject.org/docs/faq.html.en#torrc>`_. When you edit this file
you need to either restart Tor or issue a **HUP** for the changes to be
reflected. To issue a HUP you can either...

 * Run **pkill -sighup tor**.
 * Send Tor a **HUP** signal through its control port...

::

  from stem import Signal
  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()
    controller.signal(Signal.HUP)

.. _how_do_i_read_tar_xz_descriptor_archives:

How do I read \*.tar.xz descriptor archives?
--------------------------------------------

Stem's :func:`~stem.descriptor.__init__.parse_file` and
:class:`~stem.descriptor.reader.DescriptorReader`
can read plaintext descriptors and tarballs. However, `metrics uses *.xz
compression
<https://lists.torproject.org/pipermail/tor-dev/2014-May/006884.html>`_. Python
3.3 adds builtin xz support, but if you're using an earlier version of python
you will need to decompress the archives yourself.

With modern versions of tar you can simply decompress archives via **tar xf
archive.tar.xz**, or programmatically using `lzma
<https://pypi.python.org/pypi/pyliblzma>`_.

.. _what_is_that_with_keyword_i_keep_seeing_in_the_tutorials:

What is that 'with' keyword I keep seeing in the tutorials?
-----------------------------------------------------------

Python's `with <http://effbot.org/zone/python-with-statement.htm>`_ keyword
is shorthand for a try/finally block. With a :class:`~stem.control.Controller`
the following...

.. code-block:: python

  with Controller.from_port(port = 9051) as controller:
    # do my stuff

... is equivalent to...

.. code-block:: python

  controller = Controller.from_port(port = 9051)

  try:
    # do my stuff
  finally:
    controller.close()

This helps to make sure that regardless of if your code raises an exception or
not the control connection will be cleaned up afterward. Note that this means
that if you leave the 'with' scope your :class:`~stem.control.Controller` will
be closed. The following for instance is a bug common when first learning
Stem...

::

  class BandwidthReporter(object):
    def __init__(self, controller):
      self.controller = controller

    def print_bandwidth(self):
      bytes_read = self.controller.get_info("traffic/read")
      bytes_written = self.controller.get_info("traffic/written")

      print "My Tor relay has read %s bytes and written %s." % (bytes_read, bytes_written)

  if __name__ == '__main__':
    with Controller.from_port(port = 9051) as controller:
      reporter = BandwidthReporter(controller)

    # The following line is broken because the 'controller' we initialised
    # above was disconnected once we left the 'with' scope. To fix this the
    # print_bandwidth() call should be in the 'with' block.

    reporter.print_bandwidth()

Development
===========

.. _how_do_i_get_started:

How do I get started?
---------------------

The best way of getting involved with any project is to jump right in! Our `bug
tracker <https://trac.torproject.org/projects/tor/wiki/doc/stem/bugs>`_ lists
several development tasks. In particular look for the 'easy' keyword when
getting started. If you have any questions then I'm always more than happy to
help! I'm **atagar** on `oftc <http://www.oftc.net/>`_ and also available
`via email <https://www.atagar.com/contact/>`_.

To start hacking on Stem please do the following and don't hesitate to let me
know if you get stuck or would like to discuss anything!

#. Clone our `git <http://git-scm.com/>`_ repository: **git clone https://git.torproject.org/stem.git**
#. Get our test dependencies: **sudo pip install mock pycodestyle pyflakes**.
#. Find a `bug or feature <https://trac.torproject.org/projects/tor/wiki/doc/stem/bugs>`_ that sounds interesting.
#. When you have something that you would like to contribute back do the following...

 * If you don't already have a publicly accessible Stem repository then set one up. `GitHub <https://github.com/>`_ in particular is great for this.
 * File a `trac ticket <https://trac.torproject.org/projects/tor/newticket>`_, the only fields you'll need are...

  * Summary: short description of your change
  * Description: longer description and a link to your repository with either the git commits or branch that has your change
  * Type: 'defect' if this is a bug fix and 'enhancement' otherwise
  * Priority: rough guess at the priority of your change
  * Component: Core Tor / Stem

 * I'll review the change and give suggestions. When we're both happy with it I'll push your change to the official repository.

.. _how_do_i_run_the_tests:

How do I run the tests?
-----------------------

Stem has three kinds of tests: **unit**, **integration**, and **static**.

**Unit** tests are our most frequently ran tests. They're quick, they're easy,
and provide good test coverage...

::

  ~$ cd stem/
  ~/stem$ ./run_tests.py --unit

**Integration** tests start a live Tor instance and test against that. This not
only provides additional test coverage, but lets us check our continued
interoperability with new releases of Tor. Running these require that you have
`Tor installed <https://www.torproject.org/download/download.html.en>`_. You
can exercise alternate Tor configurations with the ``--target`` argument (see
``run_tests.py --help`` for a list of its options).

::

  ~/stem$ ./run_tests.py --integ
  ~/stem$ ./run_tests.py --integ --tor /path/to/tor
  ~/stem$ ./run_tests.py --integ --target RUN_COOKIE

**Static** tests use `pyflakes <https://launchpad.net/pyflakes>`_ to do static
error checking and `pycodestyle
<http://pycodestyle.readthedocs.org/en/latest/>`_ for style checking. If you
have them installed then they automatically take place as part of all test
runs.

See ``run_tests.py --help`` for more usage information.

.. _how_do_i_test_compatibility_with_multiple_python_versions:

How can I test compatibility with multiple python versions?
-----------------------------------------------------------

Stem supports python versions 2.6 and above, including the 3.x series. You can
test all versions of python you currently have installed on your system with
`tox <https://testrun.org/tox/>`_. If you're using a Debian based system this
can be as simple as...

::

  ~/stem$ sudo apt-get install python-tox python2.7 python3.3 python-dev python3-dev
  ~/stem$ tox
  ...
  ____ summary _____
    py27: commands succeeded
    py33: commands succeeded

Tox fetches Stem's dependencies for each version of python. One of these
dependencies is pycrypto which requires **python-dev** (or **python3-dev** if
testing with python3).

Tox also allows you to customize the underlying commands and environments. For
example...

:: 

  # run the tests with just python 2.6
  ~/stem$ tox -e py26

  # pass arguments to 'run_tests.py'
  ~/stem$ tox -e py26 -- -u --test response.events
 
.. _how_do_i_build_the_site:

How do I build the site?
------------------------

If you have `Sphinx <http://sphinx-doc.org/>`_ version 1.1 or later installed
then building our site is as easy as...

::

  ~$ cd stem/docs
  ~/stem/docs$ make html

When it's finished you can direct your browser to the *_build* directory with a
URI similar to...

::

  file:///home/atagar/stem/docs/_build/html/index.html

.. _what_is_the_copyright_for_patches:

What is the copyright for patches?
----------------------------------

Stem is under the LGPLv3 which is a fine license, but poses a bit of a problem
for sharing code with our other projects (which are mostly BSD). To share code
without needing to hunt down prior contributors we need Tor to have the
copyright for the whole Stem codebase. Presently the copyright of Stem is
jointly held by its main author (`Damian <https://www.atagar.com/>`_) and the
`Tor Project <https://www.torproject.org/>`_.

If you submit a substantial patch I'll ask if you're fine with it being in the
public domain. This would mean that there are no legal restrictions for using
your contribution, and hence won't pose a problem if we reuse Stem code in
other projects.

