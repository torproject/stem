# Copyright 2011-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Basic enumeration, providing ordered types for collections. These can be
constructed as simple type listings...

::

  >>> from stem.util import enum
  >>> insects = enum.Enum('ANT', 'WASP', 'LADYBUG', 'FIREFLY')
  >>> insects.ANT
  'Ant'
  >>> tuple(insects)
  ('Ant', 'Wasp', 'Ladybug', 'Firefly')

... or with overwritten string counterparts...

::

  >>> from stem.util import enum
  >>> pets = enum.Enum(('DOG', 'Skippy'), 'CAT', ('FISH', 'Nemo'))
  >>> pets.DOG
  'Skippy'
  >>> pets.CAT
  'Cat'

**Module Overview:**

::

  UppercaseEnum - Provides an enum instance with capitalized values

  Enum - Provides a basic, ordered  enumeration
    |- keys - string representation of our enum keys
    |- index_of - index of an enum value
    |- next - provides the enum after a given enum value
    |- previous - provides the enum before a given value
    |- __getitem__ - provides the value for an enum key
    +- __iter__ - iterator over our enum keys
"""

from typing import Any, Iterator, List, Sequence, Tuple, Union


def UppercaseEnum(*args: str) -> 'Enum':
  """
  Provides an :class:`~stem.util.enum.Enum` instance where the values are
  identical to the keys. Since the keys are uppercase by convention this means
  the values are too. For instance...

  ::

    >>> from stem.util import enum
    >>> runlevels = enum.UppercaseEnum('DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR')
    >>> runlevels.DEBUG
    'DEBUG'

  :param args: enum keys to initialize with

  :returns: :class:`~stem.util.enum.Enum` instance with the given keys
  """

  return Enum(*[(v, v) for v in args])


class Enum(object):
  """
  Basic enumeration.
  """

  def __init__(self, *args: Union[str, Tuple[str, Any]]) -> None:
    from stem.util.str_tools import _to_camel_case

    # ordered listings of our keys and values
    keys = []  # type: List[str]
    values = []  # type: List[Any]

    for entry in args:
      if isinstance(entry, str):
        key, val = entry, _to_camel_case(entry)
      elif isinstance(entry, tuple) and len(entry) == 2:
        key, val = entry
      else:
        raise ValueError('Unrecognized input: %s' % args)

      keys.append(key)
      values.append(val)
      setattr(self, key, val)

    self._keys = tuple(keys)
    self._values = tuple(values)

  def keys(self) -> Sequence[str]:
    """
    Provides an ordered listing of the enumeration keys in this set.

    :returns: **list** with our enum keys
    """

    return list(self._keys)

  def index_of(self, value: Any) -> int:
    """
    Provides the index of the given value in the collection.

    :param value: entry to be looked up

    :returns: **int** index of the given entry

    :raises: **ValueError** if no such element exists
    """

    return self._values.index(value)

  def next(self, value: Any) -> Any:
    """
    Provides the next enumeration after the given value.

    :param value: enumeration for which to get the next entry

    :returns: enum value following the given entry

    :raises: **ValueError** if no such element exists
    """

    if value not in self._values:
      raise ValueError('No such enumeration exists: %s (options: %s)' % (value, ', '.join(self._values)))

    next_index = (self._values.index(value) + 1) % len(self._values)
    return self._values[next_index]

  def previous(self, value: Any) -> Any:
    """
    Provides the previous enumeration before the given value.

    :param value: enumeration for which to get the previous entry

    :returns: enum value proceeding the given entry

    :raises: **ValueError** if no such element exists
    """

    if value not in self._values:
      raise ValueError('No such enumeration exists: %s (options: %s)' % (value, ', '.join(self._values)))

    prev_index = (self._values.index(value) - 1) % len(self._values)
    return self._values[prev_index]

  def __getitem__(self, item: str) -> Any:
    """
    Provides the values for the given key.

    :param item: key to look up

    :returns: value for the given key

    :raises: **ValueError** if the key doesn't exist
    """

    if item in vars(self):
      return getattr(self, item)
    else:
      keys = ', '.join(self.keys())
      raise ValueError("'%s' isn't among our enumeration keys, which includes: %s" % (item, keys))

  def __iter__(self) -> Iterator[Any]:
    """
    Provides an ordered listing of the enums in this set.
    """

    for entry in self._values:
      yield entry
