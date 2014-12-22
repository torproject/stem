Tutorial
========

.. Image Sources:
   
   * The Little Relay That Could - train.png
     Source: https://openclipart.org/detail/140185/tren-train-by-antroares
     Author: Antroares
     License: Public Domain
     Alternate: https://openclipart.org/detail/1128/train-roadsign-by-ryanlerch
   
   * To Russia With Love - soviet.png
     Source: https://openclipart.org/detail/146017/flag-of-the-soviet-union-by-marxist-leninist
     Author: Unknown
     License: Public Domain (not a subject of copyright according the Russian civil code)
     Alternate: https://openclipart.org/detail/85555/communist-sabbatarian-ribbon-by-rones-85555
   
   * Tortoise and the Hare - tortoise.png
     Source: https://openclipart.org/detail/27911/green-tortoise-%28cartoon%29-by-arking-27911
     Author: arking
     License: Public Domain
   
   * Over the River and Through the Wood - riding_hood.png
     Source: https://openclipart.org/detail/163771/little-red-riding-hood-by-tzunghaor
     Author: tzunghaor
     License: Public Domain
   
   * Mirror Mirror On The Wall - mirror.png
     Source: https://openclipart.org/detail/152155/mirror-frame-by-gsagri04
     Author: Unknown (gsagri04?)
     License: Public Domain
     Alternate: https://openclipart.org/detail/174179/miroir-rectangulaire-by-defaz36-174179
   
   * East of the Sun & West of the Moon - windrose.png
     Source: https://commons.wikimedia.org/wiki/File:Compass_card_%28sl%29.svg
     Author: Andrejj
     License: CC0 (https://creativecommons.org/publicdomain/zero/1.0/deed.en)
   
   * Mad Hatter - mad_hatter.png
     Source: http://www.krepcio.com/vitreosity/archives/MadHatter-ALL-illus600.jpg
     Author: John Tenniel
     License: Public Doman
     Augmented: Colored by me, and used the card from...
       https://openclipart.org/detail/1892/mad-hatter-with-label-on-hat-by-nayrhcrel
   
   * Double Double Toil and Trouble - cauldron.png
     Source: https://openclipart.org/detail/174099/cauldron-by-jarda-174099
     Author: Unknown (jarda?)
     License: Public Domain

Getting started with any new library can be daunting, so let's get our feet wet
by jumping straight in with some tutorials...

.. list-table::
   :widths: 1 10
   :header-rows: 0

   * - .. image:: /_static/section/tutorials/train.png
          :target: tutorials/the_little_relay_that_could.html

     - .. image:: /_static/label/the_little_relay_that_could.png
          :target: tutorials/the_little_relay_that_could.html

       Basics for talking with Tor. This will step you through configuring Tor
       and writing your first script to talk with it.

   * - .. image:: /_static/section/tutorials/soviet.png
          :target: tutorials/to_russia_with_love.html

     - .. image:: /_static/label/to_russia_with_love.png
          :target: tutorials/to_russia_with_love.html

       Rather than talking to Tor, we'll now talk **through** it. In this
       tutorial we'll programmatically start Tor then use it to read a site
       through mother Russia!

   * - .. image:: /_static/section/tutorials/tortoise.png
          :target: tutorials/tortoise_and_the_hare.html

     - .. image:: /_static/label/tortoise_and_the_hare.png
          :target: tutorials/tortoise_and_the_hare.html

       As Tor runs it generates a variety of **events** that controllers can
       subscribe to be notified of. In this tutorial we'll do just that,
       writing a curses application that graphs the bandwidth usage of Tor.

   * - .. image:: /_static/section/tutorials/riding_hood.png
          :target: tutorials/over_the_river.html

     - .. image:: /_static/label/over_the_river.png
          :target: tutorials/over_the_river.html

       `Hidden services
       <https://www.torproject.org/docs/hidden-services.html.en>`_ are a way
       of providing a service that isn't easily trackable. As a dissident, for
       instance, this could let you safely publish a blog without getting your
       door kicked down. Here we'll walk you through an example.

   * - .. image:: /_static/section/tutorials/mirror.png
          :target: tutorials/mirror_mirror_on_the_wall.html

     - .. image:: /_static/label/mirror_mirror_on_the_wall.png
          :target: tutorials/mirror_mirror_on_the_wall.html

       Getting and acting upon information about relays in the Tor network.
       Relay information is provided through documents called **descriptors**.
       This walks you through both where to get them and a small script to tell
       you the fastest Tor exits.

   * - .. image:: /_static/section/tutorials/windrose.png
          :target: tutorials/east_of_the_sun.html

     - .. image:: /_static/label/east_of_the_sun.png
          :target: tutorials/east_of_the_sun.html

       Stem provides several utility modules frequently useful for Tor
       controller applications. Here we introduce some of them.

   * - .. image:: /_static/section/tutorials/mad_hatter.png
          :target: tutorials/down_the_rabbit_hole.html

     - .. image:: /_static/label/down_the_rabbit_hole.png
          :target: tutorials/down_the_rabbit_hole.html

       Interactive interpreter for Tor that provides you with direct access to
       Tor's `control interface
       <https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_
       via either python or direct requests. This is an easy way of
       experimenting with Stem and learning what Tor can do.

   * - .. image:: /_static/section/tutorials/cauldron.png
          :target: tutorials/double_double_toil_and_trouble.html

     - .. image:: /_static/label/double_double_toil_and_trouble.png
          :target: tutorials/double_double_toil_and_trouble.html

       Sometimes it's easiest to learn a library by seeing how it's used in the
       wild. This is a directory of scripts and applications that use Stem.

