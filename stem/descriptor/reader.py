"""
Reads descriptors from local directories and archives.

Example:
  my_descriptors = [
    "/tmp/server-descriptors-2012-03.tar.bz2",
    "/tmp/archived_descriptors/",
  ]
  
  reader = DescriptorReader(my_descriptors)
  reader.start()
  
  # prints all of the descriptor contents
  for descriptor in reader:
    print descriptor
  
  reader.stop()
  reader.join()
"""

import os
import theading
import mimetypes
import Queue

class DescriptorReader(threading.Thread):
  """
  Iterator for the descriptor data on the local file system. This can process
  text files, tarball archives (gzip or bzip2), or recurse directories.
  
  This ignores files that cannot be processed (either due to read errors or
  because they don't contain descriptor data). The caller can be notified of
  files that are skipped by restering a listener with register_skip_listener().
  """
  
  def __init__(self, targets):
    self.targets = targets
    self.skip_listeners = []
    self.processed_files = {}
  
  def stop(self):
    """
    Stops further reading of descriptors.
    """
    
    pass # TODO: implement
  
  def get_processed_files(self):
    """
    For each file we have provided descriptor data for this provides a mapping
    of the form...
    
    absolute_path (str) => modified_time (int)
    
    This includes entries set through the set_processed_files() method.
    
    Returns:
      dict with the paths and unix timestamp for the last modified times of the
      files we have processed
    """
    
    return self.processed_files
  
  def set_processed_files(self, processed_files):
    """
    Appends a dictionary of 'path => modified timestamp' mappings to our
    listing of processed files. With the get_processed_files() method this can
    be used to skip descriptors that we have already read. For instance...
    
    # gets the initial descriptors
    reader = DescriptorReader(["/tmp/descriptor_data"])
    
    with reader:
      initial_descriptors = list(reader)
      processed_files = reader.get_processed_files()
    
    # only gets the descriptors that have changed since we last checked
    reader = DescriptorReader(["/tmp/descriptor_data"])
    reader.set_processed_files(processed_files)
    
    with reader:
      new_descriptors = list(reader)
    
    Arguments:
      processed_files (dict) - mapping of absolute paths (str) to unix
                               timestamps for the last modified time (int)
    """
    
    self.processed_files.update(processed_files)
  
  def register_skip_listener(self, listener):
    """
    Registers a listener for files that are skipped. This listener is expected
    to be a functor of the form...
    
    my_listener(path, exception)
    
    Arguments:
      listener (functor) - functor to be notified of files that are skipped to
                           read errors or because they couldn't be parsed as
                           valid descriptor data
    """
    
    self.skip_listeners.append(listener)
  
  def run(self):
    pass # TODO: implement
  
  def _notify_skip_listener(self, path, exception):
    for listener in self.skip_listeners:
      listener(path, exception)
  
  def __enter__(self):
    self.start()
  
  def __exit__(self, type, value, traceback):
    self.stop()
    self.join()

