Frequently Asked Questions
==========================

* **Usage**

 * :ref:`what_is_stem`
 * :ref:`does_stem_have_any_dependencies`
 * :ref:`what_python_versions_is_stem_compatible_with`
 * :ref:`what_license_is_stem_under`
 * :ref:`where_can_i_get_help`

* **Development**

 * :ref:`how_do_i_get_started`
 * :ref:`how_do_i_run_the_tests`
 * :ref:`how_do_i_build_the_site`
 * :ref:`what_is_the_copyright_for_patches`

Usage
-----

.. _what_is_stem:

What is stem?
^^^^^^^^^^^^^

Stem is a python controller library that you can use to interact with `tor <https://www.torproject.org/>`_. With it you can write scripts and applications with capabilities similar to `Vidalia <https://www.torproject.org/getinvolved/volunteer.html.en#project-vidalia>`_ and `arm <http://www.atagar.com/arm/>`_.

From a technical standpoint, stem is a python implementation of Tor's `directory <https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt>`_ and `control specifications <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_. `To get started see our tutorials! <tutorials.html>`_

.. _does_stem_have_any_dependencies:

Does stem have any dependencies?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**No.** All you need in order to use stem is python.

When it is available stem will use `pycrypto <https://www.dlitz.net/software/pycrypto/>`_ to validate descriptor signatures. However, there is no need to install pycrypto unless you need this functionality.

.. _what_python_versions_is_stem_compatible_with:

What python versions is stem compatible with?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Stem works with **python 2.6 and greater**. This includes the python 3.x series by installing stem via python3 (see our `installation instructions <https://pypi.python.org/pypi/stem/>`_ for more information).

.. _what_license_is_stem_under:

What license is stem under?
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Stem is under the `LGPLv3 <https://www.gnu.org/licenses/lgpl>`_.

.. _where_can_i_get_help:

Where can I get help?
^^^^^^^^^^^^^^^^^^^^^

Do you have a tor related question or project that you would like to discuss? If so then find us on the `tor-dev@ email list <https://lists.torproject.org/cgi-bin/mailman/listinfo/tor-dev>`_ and `IRC <https://www.torproject.org/about/contact.html.en#irc>`_.

Development
-----------

.. _how_do_i_get_started:

How do I get started?
^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^

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

**Static** tests use `pyflakes <https://launchpad.net/pyflakes>`_ to do static error checking and `pep8 <http://pep8.readthedocs.org/en/latest/>`_ for style checking. If you have them installed then pyflakes automatically takes place as part of all test runs, but static checking is run separately...

::

  ~/stem$ ./run_tests.py --style

If you have **python 3** installed then you can test our python 3 compatibility with the following. *Note that need to still initially execute run_tests.py with a 2.x version of python.*

::

  ~/stem$ ./run_tests.py --all --python3

See ``run_tests.py --help`` for more usage information.

.. _how_do_i_build_the_site:

How do I build the site?
^^^^^^^^^^^^^^^^^^^^^^^^

If you have `sphinx <http://sphinx-doc.org/>`_ version 1.1 or later installed then building our site is as easy as...

::

  ~$ cd stem/docs
  ~/stem/docs$ make html

When it's finished you can direct your browser to the *_build* directory with a URI similar to...

::

  file:///home/atagar/stem/docs/_build/html/index.html

.. _what_is_the_copyright_for_patches:

What is the copyright for patches?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Stem is under the LGPLv3 which is a fine license, but poses a bit of a problem for sharing code with our other projects (which are mostly BSD). To share code without needing to hunt down prior contributors we need an individual to have the copyright for the whole stem codebase. This is Damian at present, but I'll probably give it to Tor if I get nailed by a bus.

If you submit a substantial patch I'll ask if you're fine with it being in the public domain. This would mean that there are no legal restrictions for using your contribution, and hence won't pose a problem if we reuse stem code in other projects.

