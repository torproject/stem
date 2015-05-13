Over the River and Through the Wood
===================================

`Hidden services <https://www.torproject.org/docs/hidden-services.html.en>`_
give you a way of providing a service without exposing your address. These
services are only accessible through Tor or `Tor2web <https://tor2web.org/>`_,
and useful for a surprising number of things...

* **Hosting an anonymized site**. This is usually the first thing that comes to
  mind, and something we'll demonstrate in a sec.

* Providing an **endpoint Tor users can reach** without exiting the Tor
  network. This eliminates the risk of an unreliable or malicious exit getting
  in the way. Great examples of this are `Facebook
  <http://arstechnica.com/security/2014/10/facebook-offers-hidden-service-to-tor-users/>`_
  (*facebookcorewwwi.onion*) and `DuckDuckGo
  <https://lists.torproject.org/pipermail/tor-talk/2010-August/003095.html>`_
  (*3g2upl4pq6kufc4m.onion*).

* **Personal services**. For instance you can host your home SSH server as a
  hidden service to prevent eavesdroppers from knowing where you live while
  traveling abroad.

`Tor2web <https://tor2web.org/>`_ provides a quick and easy way of seeing if
your hidden service is working. To use it simply replace the **.onion** of
your address with **.tor2web.org**...

.. image:: /_static/duck_duck_go_hidden_service.png
   :target: https://3g2upl4pq6kufc4m.tor2web.org/

.. _running-a-hidden-service:

Running a hidden service
------------------------

Hidden services can be `configured through your torrc
<https://www.torproject.org/docs/tor-manual.html.en#_hidden_service_options>`_,
but Stem also provides some methods to easily work with them...

  * :func:`~stem.control.Controller.create_hidden_service`
  * :func:`~stem.control.Controller.remove_hidden_service`
  * :func:`~stem.control.Controller.get_hidden_service_conf`
  * :func:`~stem.control.Controller.set_hidden_service_conf`

The main threat to your anonymity when running a hidden service is the service
itself. Debug information for instance might leak your real address,
undermining what Tor provides. This includes the following example, **do not
rely on it not to leak**.

But with that out of the way lets take a look at a simple `Flask
<http://flask.pocoo.org/>`_ example based on one by `Jordan Wright
<https://jordan-wright.github.io/blog/2014/10/06/creating-tor-hidden-services-with-python/>`_...

::

  import os
  import shutil

  from stem.control import Controller
  from flask import Flask

  app = Flask(__name__)


  @app.route('/')
  def index():
    return "<h1>Hi Grandma!</h1>"


  print ' * Connecting to tor'

  with Controller.from_port() as controller:
    controller.authenticate()

    # All hidden services have a directory on disk. Lets put ours in tor's data
    # directory.

    hidden_service_dir = os.path.join(controller.get_conf('DataDirectory', '/tmp'), 'hello_world')

    # Create a hidden service where visitors of port 80 get redirected to local
    # port 5000 (this is where Flask runs by default).

    print " * Creating our hidden service in %s" % hidden_service_dir
    result = controller.create_hidden_service(hidden_service_dir, 80, target_port = 5000)

    # The hostname is only available when we can read the hidden service
    # directory. This requires us to be running with the same user as tor.

    if result.hostname:
      print " * Our service is available at %s, press ctrl+c to quit" % result.hostname
    else:
      print " * Unable to determine our service's hostname, probably due to being unable to read the hidden service directory"

    try:
      app.run()
    finally:
      # Shut down the hidden service and clean it off disk. Note that you *don't*
      # want to delete the hidden service directory if you'd like to have this
      # same *.onion address in the future.

      print " * Shutting down our hidden service"
      controller.remove_hidden_service(hidden_service_dir)
      shutil.rmtree(hidden_service_dir)

Now if we run this...

::

  % python example.py 
   * Connecting to tor
   * Creating our hidden service in /home/atagar/.tor/hello_world
   * Our service is available at uxiuaxejc3sxrb6i.onion, press ctrl+c to quit
   * Running on http://127.0.0.1:5000/
  127.0.0.1 - - [15/Dec/2014 13:05:43] "GET / HTTP/1.1" 200 -
   * Shutting down our hidden service

... we'll have a service we can visit via the `Tor Browser Bundle <https://www.torproject.org/download/download-easy.html.en>`_...

.. image:: /_static/hidden_service.png

.. _ephemeral-hidden-services:

Ephemeral hidden services
-------------------------

In the above example you may have noticed the note that said...

::

  # The hostname is only available when we can read the hidden service
  # directory. This requires us to be running with the same user as tor.

This has been a limitation of hidden services for years. However, as of version
0.2.7.1 Tor offers another style for making services called **ephemeral hidden
services**.

Ephemeral hidden services do not touch disk, and as such are easier to work
with but require you to persist your service's private key yourself if you want
to reuse a '.onion' address.

Ephemeral services can only be created through the controller, and only exist
as long as your controller is attached unless you provide the **detached**
flag. Controllers can only see their own ephemeral services, and ephemeral
services that are detached. In other words, attached ephemeral services can
only be managed by their own controller.

Stem provides three methods to work with ephemeral hidden services...

  * :func:`~stem.control.Controller.list_ephemeral_hidden_services`
  * :func:`~stem.control.Controller.create_ephemeral_hidden_service`
  * :func:`~stem.control.Controller.remove_ephemeral_hidden_service`

For example, with a ephemeral service our earlier example becomes as simple as...

::

  from stem.control import Controller
  from flask import Flask

  app = Flask(__name__)


  @app.route('/')
  def index():
    return "<h1>Hi Grandma!</h1>"


  print ' * Connecting to tor'

  with Controller.from_port() as controller:
    controller.authenticate()

    # Create a hidden service where visitors of port 80 get redirected to local
    # port 5000 (this is where Flask runs by default).

    print " * Creating our hidden service in %s" % hidden_service_dir
    response = controller.create_ephemeral_hidden_service({80: 5000}, await_publication = True)
    print " * Our service is available at %s.onion, press ctrl+c to quit" % response.service_id

    try:
      app.run()
    finally:
      print " * Shutting down our hidden service"

.. _hidden-service-descriptors:

Hidden service descriptors
--------------------------

Like relays, hidden services publish documents about themselves called **hidden
service descriptors**. These contain low level details for establishing
connections. Hidden service descriptors are available from the tor process via
its :func:`~stem.control.Controller.get_hidden_service_descriptor` method...

::

  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()

    # descriptor of duck-duck-go's hidden service (http://3g2upl4pq6kufc4m.onion)

    print controller.get_hidden_service_descriptor('3g2upl4pq6kufc4m')

::

  % python print_duck_duck_go_descriptor.py

  rendezvous-service-descriptor e5dkwgp6vt7axoozixrbgjymyof7ab6u
  version 2
  permanent-key
  -----BEGIN RSA PUBLIC KEY-----
  MIGJAoGBAJ/SzzgrXPxTlFrKVhXh3buCWv2QfcNgncUpDpKouLn3AtPH5Ocys0jE
  aZSKdvaiQ62md2gOwj4x61cFNdi05tdQjS+2thHKEm/KsB9BGLSLBNJYY356bupg
  I5gQozM65ENelfxYlysBjJ52xSDBd8C4f/p9umdzaaaCmzXG/nhzAgMBAAE=
  -----END RSA PUBLIC KEY-----
  secret-id-part bmsctib2pzirgo7cltlxdm5fxqcitt5e
  publication-time 2015-05-11 20:00:00
  protocol-versions 2,3
  introduction-points
  -----BEGIN MESSAGE-----
  aW50cm9kdWN0aW9uLXBvaW50IHZzcm4ycGNtdzNvZ21mNGo3dGpxeHptdml1Y2Rr
  NGtpCmlwLWFkZHJlc3MgMTc2LjkuNTkuMTcxCm9uaW9uLXBvcnQgOTAwMQpvbmlv
  ... etc...

A hidden service's introduction points are a base64 encoded field that's
possibly encrypted. These can be decoded (and decrypted if necessary) with the
descriptor's
:func:`~stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor.introduction_points`
method.

::

  from stem.control import Controller

  with Controller.from_port(port = 9051) as controller:
    controller.authenticate()
    desc = controller.get_hidden_service_descriptor('3g2upl4pq6kufc4m')

    print "DuckDuckGo's introduction points are...\n"

    for introduction_point in desc.introduction_points():
      print '  %s:%s => %s' % (introduction_point.address, introduction_point.port, introduction_point.identifier)

::

  % python print_duck_duck_go_introduction_points.py

  DuckDuckGo's introduction points are...

    176.9.59.171:9001 => vsrn2pcmw3ogmf4j7tjqxzmviucdk4ki
    104.131.106.181:9001 => gcl2kpqx5qnkpgxjf6x7ulqncoqj7ghh
    188.166.58.218:443 => jeymnbhs2d6l2oib7jjvweavg45m6gju

