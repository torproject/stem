Frequently Asked Questions
==========================

* **General Information**

 * :ref:`what_is_stem`
 * :ref:`does_stem_have_any_dependencies`
 * :ref:`what_python_versions_is_stem_compatible_with`
 * :ref:`what_license_is_stem_under`
 * :ref:`are_there_any_other_controller_libraries`
 * :ref:`where_can_i_get_help`

* **Usage**

 * :ref:`how_do_i_request_a_new_identity_from_tor`
 * :ref:`how_do_i_get_information_about_my_exits`
 * :ref:`how_do_i_reload_my_torrc`
 * :ref:`what_is_that_with_keyword_i_keep_seeing_in_the_tutorials`

* **Development**

 * :ref:`how_do_i_get_started`
 * :ref:`how_do_i_run_the_tests`
 * :ref:`how_do_i_build_the_site`
 * :ref:`what_is_the_copyright_for_patches`

General Information
===================

.. _what_is_stem:

What is stem?
-------------

Stem is a python controller library that you can use to interact with `tor <https://www.torproject.org/>`_. With it you can write scripts and applications with capabilities similar to `Vidalia <https://www.torproject.org/getinvolved/volunteer.html.en#project-vidalia>`_ and `arm <http://www.atagar.com/arm/>`_.

From a technical standpoint, stem is a python implementation of Tor's `directory <https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt>`_ and `control specifications <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_. `To get started see our tutorials! <tutorials.html>`_

.. _does_stem_have_any_dependencies:

Does stem have any dependencies?
--------------------------------

**No.** All you need in order to use stem is python.

When it is available stem will use `pycrypto <https://www.dlitz.net/software/pycrypto/>`_ to validate descriptor signatures. However, there is no need to install pycrypto unless you need this functionality.

.. _what_python_versions_is_stem_compatible_with:

What python versions is stem compatible with?
---------------------------------------------

Stem works with **python 2.6 and greater**. This includes the python 3.x series by installing stem via python3 (see our `installation instructions <https://pypi.python.org/pypi/stem/>`_ for more information).

.. _what_license_is_stem_under:

What license is stem under?
---------------------------

Stem is under the `LGPLv3 <https://www.gnu.org/licenses/lgpl>`_.

.. _are_there_any_other_controller_libraries:

Are there any other controller libraries?
-----------------------------------------

Yup. The most mature controller libraries are written in python, but there's a few options in other languages as well. By far the most mature alternative to Stem are `Txtorcon <https://txtorcon.readthedocs.org/>`_ and `TorCtl <https://gitweb.torproject.org/pytorctl.git>`_.

`Txtorcon <https://txtorcon.readthedocs.org/>`_ is an actively maintained controller library written by Meejah for `Twisted <https://twistedmatrix.com/trac/>`_. In the future we plan to `integrate Stem and Txtorcon <https://www.torproject.org/getinvolved/volunteer.html.en#txtorcon-stemIntegration>`_ to some degree, but that is still a ways off.

`TorCtl <https://gitweb.torproject.org/pytorctl.git>`_ is Stem's predecessor and `deprecated in December 2012 <https://blog.torproject.org/blog/torctl-deprecation-and-stem-plans>`_ in favor of Stem. Though no longer actively developed, it's still quite functional and still used for several `TorFlow <https://gitweb.torproject.org/torflow.git>`_ based projects.

The following are the functional controller libraries I'm aware of. Dates are for highly active development. If I missed one then please `let me know <http://www.atagar.com/contact/>`_!

==========================================================  ================    =======================
Library                                                     Language            Developed
==========================================================  ================    =======================
`Stem <https://stem.torproject.org/>`_                      Python              October 2011 - Present
`Txtorcon <https://txtorcon.readthedocs.org/>`_             Python (Twisted)    February 2012 - Present
`TorCtl <https://gitweb.torproject.org/pytorctl.git>`_      Python              July 2008 - November 2011
`PHP TorCtl <https://github.com/dunglas/php-torcontrol/>`_  PHP                 February 2013
`JTorCtl <https://gitweb.torproject.org/jtorctl.git>`_      Java                June 2005 - May 2009
==========================================================  ================    =======================

.. _where_can_i_get_help:

Where can I get help?
---------------------

Do you have a tor related question or project that you would like to discuss? If so then find us on the `tor-dev@ email list <https://lists.torproject.org/cgi-bin/mailman/listinfo/tor-dev>`_ and `IRC <https://www.torproject.org/about/contact.html.en#irc>`_.

Usage
=====

.. _how_do_i_request_a_new_identity_from_tor:

How do I request a new identity from Tor?
-----------------------------------------

In Tor your identity is the three-hop **circuit** over which your traffic travels through the Tor network.

Tor periodically creates new circuits. When a circuit is used it becomes **dirty**, and after ten minutes new connections will not use it. When all of the connections using an expired circuit are done the circuit is closed.

An important thing to note is that a new circuit does not necessarily mean a new IP address. Paths are randomly selected based on heuristics like speed and stability. There are only so many large exits in the Tor network, so it's not uncommon to reuse an exit you have had previously.

Tor does not have a method for cycling your IP address. This is on purpose, and done for a couple reasons. The first is that this capability is usually requested for not-so-nice reasons such as ban evasion or SEO. Second, repeated circuit creation puts a very high load on the Tor network, so please don't!

With all that out of the way, how do you create a new circuit? You can customise the rate at which Tor cycles circuits with the **MaxCircuitDirtiness** option in your `torrc <https://www.torproject.org/docs/faq.html.en#torrc>`_. `Vidalia <https://www.torproject.org/getinvolved/volunteer.html.en#project-vidalia>`_ and `arm <http://www.atagar.com/arm/>`_ both provide a method to request a new identity, and you can do so programmatically by sending Tor a NEWNYM signal.

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

And with stem...

::

  from stem import Signal
  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()
    controller.signal(Signal.NEWNYM)

For lower level control over Tor's circuits and path selection see the `client usage tutorial <tutorials/to_russia_with_love.html>`_.

.. _how_do_i_get_information_about_my_exits:

How do I get information about my exits?
----------------------------------------

To learn about the Tor relays you're presently using call :func:`~stem.control.Controller.get_circuits`. The last relay in the circuit's path is your exit...

::

  from stem import CircStatus
  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    for circ in controller.get_circuits():
      if circ.status != CircStatus.BUILT:
        continue

      exit_fp, exit_nickname = circ.path[-1]

      exit_desc = controller.get_network_status(exit_fp, None)
      exit_address = exit_desc.address if exit_desc else 'unknown'

      print "Exit relay"
      print "  fingerprint: %s" % exit_fp
      print "  nickname: %s" % exit_nickname
      print "  address: %s" % exit_address
      print

::

  % python example.py 
  Exit relay
    fingerprint: 94AD3437EC49A31E8D6C17CC3BDE8316C90262BE
    nickname: davidonet
    address: 188.165.236.209

  Exit relay
    fingerprint: 6042CC1C69BBFE83A1DD2BCD4C15000A0DD5E1BC
    nickname: Gnome5
    address: 178.209.50.230

  Exit relay
    fingerprint: 9634F910C2942A2E46720DD161A873E3A619AD90
    nickname: veebikaamera
    address: 81.21.246.66

  Exit relay
    fingerprint: A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7
    nickname: chaoscomputerclub19
    address: 31.172.30.2

.. _how_do_i_reload_my_torrc:

How do I reload my torrc?
-------------------------

Tor is configured through its `torrc <https://www.torproject.org/docs/faq.html.en#torrc>`_. When you edit this file you need to either restart Tor or issue a **SIGHUP** for the changes to be reflected. To issue a SIGHUP you can either...

 * Run **pkill -sighup tor**.
 * Send Tor a **SIGHUP** signal through its control port...

::

  from stem import Signal
  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()
    controller.signal(Signal.SIGHUP)

.. _what_is_that_with_keyword_i_keep_seeing_in_the_tutorials:

What is that 'with' keyword I keep seeing in the tutorials?
-----------------------------------------------------------

Python's '**with**' keyword is shorthand for a try/finally block. With a :class:`~stem.control.Controller` the following...

::

  with Controller.from_port(port = 9051) as controller:
    # do my stuff

... is equivialnt to...

::

  controller = Controller.from_port(port = 9051)

  try:
    # do my stuff
  finally:
    controller.close()

This helps to make sure that regardless of if your code raises an exception or not the control connection will be cleaned up afterward. Note that this means that if you leave the 'with' scope your :class:`~stem.control.Controller` will be closed. For instance...

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
    # above was disconnected once we left the 'with' scope.

    reporter.print_bandwidth()

To fix this we could either move the print_bandwidth() call into the 'with' scope, or simply avoid using 'with' all together...

::

  if __name__ == '__main__':
    controller = Controller.from_port(port = 9051)

    try:
      reporter = BandwidthReporter(controller)
      reporter.print_bandwidth()
    finally:
      controller.close()

For more information about the 'with' keyword see `here <http://effbot.org/zone/python-with-statement.htm>`_.

Development
===========

.. _how_do_i_get_started:

How do I get started?
---------------------

The best way of getting involved with any project is to jump right in! Our `bug tracker <https://trac.torproject.org/projects/tor/wiki/doc/stem/bugs>`_ lists several development tasks. In particular look for the 'easy' keyword when getting started.

If you have any questions then I'm always more than happy to help (I'm **atagar** on `oftc <http://www.oftc.net/oftc/>`_ and also available `via email <http://www.atagar.com/contact/>`_).

To start hacking on stem please do the following and don't hesitate to let me know if you get stuck or would like to discuss anything!

1. Clone our `git <http://git-scm.com/>`_ repository: **git clone https://git.torproject.org/stem.git**
2. Find a `bug or feature <https://trac.torproject.org/projects/tor/wiki/doc/stem/bugs>`_ that sounds interesting.
3. When you have something that you would like to contribute back do the following...

 * If you don't already have a publicly accessible stem repository then set one up. `GitHub <https://github.com/>`_ in particular is great for this.
 * File a `trac ticket <https://trac.torproject.org/projects/tor/newticket>`_, the only fields you'll need are...

  * Summary: short description of your change
  * Description: longer description and a link to your repository with either the git commits or branch that has your change
  * Type: 'defect' if this is a bug fix and 'enhancement' otherwise
  * Priority: rough guess at the priority of your change
  * Component: Stem

 * I'll review the change and give suggestions. When we're both happy with it I'll push your change to the official repository.

.. _how_do_i_run_the_tests:

How do I run the tests?
-----------------------

Stem has three kinds of tests: **unit**, **integration**, and **static**.

**Unit** tests are our most frequently ran tests. They're quick, they're easy, and provide good test coverage...

::

  ~$ cd stem/
  ~/stem$ ./run_tests.py --unit

**Integration** tests start a live tor instance and test against that. This not only provides additional test coverage, but lets us check our continued interoperability with new releases of tor. Running these require that you have `tor installed <https://www.torproject.org/download/download.html.en>`_. You can exercise alternate tor configurations with the ``--target`` argument (see ``run_tests.py --help`` for a list of its options).

::

  ~/stem$ ./run_tests.py --integ
  ~/stem$ ./run_tests.py --integ --tor /path/to/tor
  ~/stem$ ./run_tests.py --integ --target RUN_COOKIE

**Static** tests use `pyflakes <https://launchpad.net/pyflakes>`_ to do static error checking and `pep8 <http://pep8.readthedocs.org/en/latest/>`_ for style checking. If you have them installed then pyflakes automatically takes place as part of all test runs, but style checking is run separately...

::

  ~/stem$ ./run_tests.py --style

If you have **python 3** installed then you can test our python 3 compatibility with the following. *Note that need to still initially execute run_tests.py with a 2.x version of python.*

::

  ~/stem$ ./run_tests.py --all --python3

See ``run_tests.py --help`` for more usage information.

.. _how_do_i_build_the_site:

How do I build the site?
------------------------

If you have `sphinx <http://sphinx-doc.org/>`_ version 1.1 or later installed then building our site is as easy as...

::

  ~$ cd stem/docs
  ~/stem/docs$ make html

When it's finished you can direct your browser to the *_build* directory with a URI similar to...

::

  file:///home/atagar/stem/docs/_build/html/index.html

.. _what_is_the_copyright_for_patches:

What is the copyright for patches?
----------------------------------

Stem is under the LGPLv3 which is a fine license, but poses a bit of a problem for sharing code with our other projects (which are mostly BSD). To share code without needing to hunt down prior contributors we need Tor to have the copyright for the whole stem codebase. Presently the copyright of stem is jointly held by its main author (`Damian <http://www.atagar.com/>`_) and the `Tor Project <https://www.torproject.org/>`_.

If you submit a substantial patch I'll ask if you're fine with it being in the public domain. This would mean that there are no legal restrictions for using your contribution, and hence won't pose a problem if we reuse stem code in other projects.

