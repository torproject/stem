"""
Basic enumeration, providing ordered types for collections. These can be
constructed as simple type listings, ie:
>>> insects = Enum("ANT", "WASP", "LADYBUG", "FIREFLY")
>>> insects.ANT
'Ant'
>>> insects.values()
['Ant', 'Wasp', 'Ladybug', 'Firefly']

with overwritten string counterparts:
>>> pets = Enum(("DOG", "Skippy"), "CAT", ("FISH", "Nemo"))
>>> pets.DOG
'Skippy'
>>> pets.CAT
'Cat'

or with entirely custom string components as an unordered enum with:
>>> pets = LEnum(DOG="Skippy", CAT="Kitty", FISH="Nemo")
>>> pets.CAT
'Kitty'
"""

def to_camel_case(label, word_divider = " "):
  """
  Converts the given string to camel case, ie:
  >>> to_camel_case("I_LIKE_PEPPERJACK!")
  'I Like Pepperjack!'
  
  Arguments:
    label (str)        - input string to be converted
    word_divider (str) - string used to replace underscores
  """
  
  words = []
  for entry in label.split("_"):
    if len(entry) == 0: words.append("")
    elif len(entry) == 1: words.append(entry.upper())
    else: words.append(entry[0].upper() + entry[1:].lower())
  
  return word_divider.join(words)

class Enum:
  """
  Basic enumeration.
  """
  
  def __init__(self, *args):
    # ordered listings of our keys and values
    keys, values = [], []
    
    for entry in args:
      if isinstance(entry, str):
        key, val = entry, to_camel_case(entry)
      elif isinstance(entry, tuple) and len(entry) == 2:
        key, val = entry
      else: raise ValueError("Unrecognized input: %s" % args)
      
      keys.append(key)
      values.append(val)
      self.__dict__[key] = val
    
    self._keys = tuple(keys)
    self._values = tuple(values)
  
  def keys(self):
    """
    Provides an ordered listing of the enumeration keys in this set.
    
    Returns:
      tuple with our enum keys
    """
    
    return self._keys
  
  def values(self):
    """
    Provides an ordered listing of the enumerations in this set.
    
    Returns:
      tuple with our enum values
    """
    
    return self._values
  
  def index_of(self, value):
    """
    Provides the index of the given value in the collection.
    
    Arguments:
      value - entry to be looked up
    
    Returns:
      integer index of the given entry
    
    Raises:
      ValueError if no such element exists
    """
    
    return self._values.index(value)
  
  def next(self, value):
    """
    Provides the next enumeration after the given value.
    
    Arguments:
      value - enumeration for which to get the next entry
    
    Returns:
      enum value following the given entry
    
    Raises:
      ValueError if no such element exists
    """
    
    if not value in self._values:
      raise ValueError("No such enumeration exists: %s (options: %s)" % (value, ", ".join(self._values)))
    
    next_index = (self._values.index(value) + 1) % len(self._values)
    return self._values[next_index]
  
  def previous(self, value):
    """
    Provides the previous enumeration before the given value.
    
    Arguments:
      value - enumeration for which to get the previous entry
    
    Returns:
      enum value proceeding the given entry
    
    Raises:
      ValueError if no such element exists
    """
    
    if not value in self._values:
      raise ValueError("No such enumeration exists: %s (options: %s)" % (value, ", ".join(self._values)))
    
    prev_index = (self._values.index(value) - 1) % len(self._values)
    return self._values[prev_index]

class LEnum(Enum):
  """
  Enumeration that accepts custom string mappings.
  """
  
  def __init__(self, **args):
    Enum.__init__(self)
    self.__dict__.update(args)
    self._values = sorted(args.values())

