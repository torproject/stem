Change Log
==========

The following is a log of all user-facing changes to stem, both released and
unreleased. For a monthly report on work being done see my `development log
<http://www.atagar.com/log.php>`_.

* :ref:`versioning`
* :ref:`unreleased`
* :ref:`version_1.0`

.. _versioning:

Versioning
----------

Stem uses `semantic versioning <http://semver.org/>`_, which means that
**versions consist of three numbers** (such as '**1.2.4**'). These are used to
convey the kind of backward compatibility a release has...

 * The first value is the **major version**. This changes infrequently, and
   indicates that backward incompatible changes have been made (such as the
   removal of deprecated functions).

 * The second value is the **minor version**. This is the most common kind of
   release, and denotes that the improvements are backward compatible.

 * The third value is the **patch version**. When a stem release has a major
   issue another release is made which fixes just that problem. These do not
   contain substantial improvements or new features. This value is sometimes
   left off to indicate all releases with a given major/minor version.

.. _unreleased:

Unreleased
----------

The following are only available within stem's `git repository
<download.html>`_.

 * **Controller**

  * :func:`~stem.control.Controller.get_network_status` and :func:`~stem.control.Controller.get_network_statuses` now provide v3 rather than v2 directory information (:trac:`7953`, :spec:`d2b7ebb`)
  * :class:`~stem.response.events.AddrMapEvent` support for the new CACHED argument (:trac:`8596`, :spec:`25b0d43`)
  * :func:`~stem.control.Controller.attach_stream` could encounter an undocumented 555 response (:trac:`8701`, :spec:`7286576`)
  * :class:`~stem.descriptor.server_descriptor.RelayDescriptor` digest validation was broken when dealing with non-unicode content with python 3 (:trac:`8755`)
  * The :class:`~stem.control.Controller` use of cached content wasn't thread safe (:trac:`8607`)
  * Added :func:`~stem.control.Controller.get_user` method to the :class:`~stem.control.Controller`
  * Added :func:`~stem.control.Controller.get_pid` method to the :class:`~stem.control.Controller`
  * :class:`~stem.response.events.StreamEvent` didn't recognize IPv6 addresses (:trac:`9181`)

 * **Descriptors**

  * Added the `stem.descriptor.remote <api/descriptor/remote.html>`_ module.
  * The :class:`~stem.descriptor.reader.DescriptorReader` mishandled relative paths (:trac:`8815`)

 * **Utilities**

  * :func:`~stem.util.system.set_process_name` inserted spaces between characters (:trac:`8631`)
  * :func:`~stem.util.system.get_pid_by_name` can now pull for all processes with a given name
  * :func:`~stem.util.system.call` ignored the subprocess' exit status
  * Added :func:`stem.util.system.get_user`
  * Added :func:`stem.util.system.get_start_time`
  * Added :func:`stem.util.system.get_bsd_jail_path`

 * **Website**

  * Overhaul of stem's `download page <download.html>`_. This included several
    improvements, most notably the addition of PyPI, Ubuntu, Fedora, Slackware,
    and FreeBSD.
  * Replaced default sphinx header with a navbar menu.
  * Added this change log.
  * Added the `FAQ page <faq.html>`_.
  * Settled on a `logo
    <http://www.wpclipart.com/plants/assorted/P/plant_stem.png.html>`_ for
    stem.
  * Expanded the `client usage tutorial <tutorials/to_russia_with_love.html>`_
    to cover SocksiPy and include an example for polling Twitter.
  * Subtler buttons for the frontpage (`before
    <http://www.atagar.com/transfer/stem_frontpage/before.png>`_ and `after
    <http://www.atagar.com/transfer/stem_frontpage/after.png>`_).

.. _version_1.0:

Version 1.0
-----------

This was the `initial release of stem
<https://blog.torproject.org/blog/stem-release-10>`_, made on **March 26th,
2013**.

 * **Version 1.0.1** (March 27th, 2013) - fixed an issue where installing with
   python 3.x (python3 setup.py install) resulted in a stacktrace

