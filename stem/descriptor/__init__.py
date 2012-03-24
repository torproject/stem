"""
Package for parsing and processing descriptor data.
"""

__all__ = ["descriptor", "reader", "server_descriptor", "parse_descriptors", "Descriptor"]

import os

def parse_descriptors(path, descriptor_file):
  """
  Provides an iterator for the descriptors within a given file.
  
  Arguments:
    path (str)             - absolute path to the file's location on disk
    descriptor_file (file) - opened file with the descriptor contents
  
  Returns:
    iterator that parses the file's contents into descriptors
  
  Raises:
    TypeError if we can't match the contents of the file to a descriptor type
    IOError if unable to read from the descriptor_file
  """
  
  import stem.descriptor.server_descriptor
  
  # The tor descriptor specifications do not provide a reliable method for
  # identifying a descriptor file's type and version so we need to guess
  # based on its filename for resources from the data directory and contents
  # for files provided by metrics.
  
  filename = os.path.basename(path)
  
  if filename == "cached-descriptors":
    # server descriptors from tor's data directory
    while descriptor_file:
      yield stem.descriptor.server_descriptor.parse_server_descriptors_v2(path, descriptor_file)
    
    return
  
  first_line = descriptor_file.readline()
  descriptor_file.seek(0)
  
  if first_line.startswith("router "):
    # server descriptor
    while descriptor_file:
      yield stem.descriptor.server_descriptor.parse_server_descriptors_v2(path, descriptor_file)
    
    return
  
  # TODO: implement actual descriptor type recognition and parsing
  # TODO: add integ test for non-descriptor text content
  yield Descriptor(path, descriptor_file.read())

class Descriptor:
  """
  Common parent for all types of descriptors.
  """
  
  def __init__(self, contents):
    self._path = None
    self._raw_contents = contents
  
  def get_path(self):
    """
    Provides the absolute path that we loaded this descriptor from.
    
    Returns:
      str with the absolute path of the descriptor source
    """
    
    return self._path
  
  def get_unrecognized_lines(self):
    """
    Provides a list of lines that were either ignored or had data that we did
    not know how to process. This is most common due to new descriptor fields
    that this library does not yet know how to process. Patches welcome!
    
    Returns:
      list of lines of unrecognized content
    """
    
    return []
  
  def _set_path(self, path):
    self._path = path
  
  def __str__(self):
    return self._raw_contents


