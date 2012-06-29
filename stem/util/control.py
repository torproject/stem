"""
Helper functions utilized by the controller classes.

**Module Overview:**

::
  case_insensitive_lookup - does case insensitive lookups on python dictionaries
"""

def case_insensitive_lookup(lst, key, start=None, stop=None):
  """
  Returns the first value equal to key in lst while ignoring case.
  
  :param list lst: list of strings
  :param str key: string to be looked up
  :param int start: index from where the lookup should begin
  :param int stop: index where the lookup ends
  
  :returns: case-insensitive equivalent of key in lst
  
  :raises: ValueError if such a key doesn't exist
  """
  
  for i in lst[start:stop]:
    if i.lower() == key.lower():
      return i
