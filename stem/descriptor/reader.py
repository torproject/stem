"""
Utilities for reading descriptors from local directories and archives. This is
mostly done through the DescriptorReader class, which is an iterator for the
descriptor data in a series of destinations. For example...

  my_descriptors = [
    "/tmp/server-descriptors-2012-03.tar.bz2",
    "/tmp/archived_descriptors/",
  ]
  
  reader = DescriptorReader(my_descriptors)
  
  # prints the contents of all the descriptor files
  with reader:
    for descriptor in reader:
      print descriptor

This ignores files that cannot be processed due to read errors or unparsable
content. To be notified of skipped files you can register a listener with
register_skip_listener().

The DescriptorReader keeps track of the last modified timestamps for descriptor
files that it has read so it can skip unchanged files if ran again. This
listing of processed files can also be persisted and applied to other
DescriptorReaders. For instance, the following prints descriptors as they're
changed over the course of a minute, and picks up where it left off if ran
again...

  reader = DescriptorReader(["/tmp/descriptor_data"])
  
  try:
    processed_files = load_processed_files("/tmp/used_descriptors")
    reader.set_processed_files(processed_files)
  except: pass # could not load, mabye this is the first run
  
  with reader:
    start_time = time.time()
    
    while time.time() - start_time < 60:
      # prints any descriptors that have changed since last checked
      for descriptor in reader:
        print descriptor
      
      time.sleep(1)
  
  save_processed_files(reader.get_processed_files(), "/tmp/used_descriptors")


load_processed_files - Loads a listing of processed files.
save_processed_files - Saves a listing of processed files.

DescriptorReader - Iterator for descriptor data on the local file system.
  |- get_processed_files - provides the listing of files that we've processed
  |- set_processed_files - sets our tracking of the files we have processed
  |- register_skip_listener - adds a listener that's notified of skipped files
  |- start - begins reading descriptor data
  |- stop - stops reading descriptor data
  |- join - joins on the thread used to process descriptor data
  |- __enter__ / __exit__ - manages the descriptor reader thread in the context
  +- __iter__ - iterates over descriptor data in unread files
"""

import os
import threading
import mimetypes
import Queue

# TODO: Unimplemented concurrency features...
# - restarting when __iter__ is called additional times
# - maximum read-ahead

# TODO: Remianing impementation items...
# - integ test that we skip the 'processed files' items
# - impelment skip listening and add a test for it
# - remove start and join methods from header?
# - implement gzip and bz2 reading

# Maximum number of descriptors that we'll read ahead before waiting for our
# caller to fetch some of them. This is included to avoid unbounded memory
# usage. This condition will be removed if set to zero.

MAX_STORED_DESCRIPTORS = 20

def load_processed_files(path):
  """
  Loads a dictionary of 'path => last modified timestamp' mappings, as
  persisted by save_processed_files(), from a file.
  
  Arguments:
    path (str) - location to load the processed files dictionary from
  
  Returns:
    dict of 'path (str) => last modified unix timestamp (int)' mappings
  
  Raises:
    IOError if unable to read the file
    TypeError if unable to parse the file's contents
  """
  
  processed_files = {}
  
  with open(path) as input_file:
    for line in input_file.readlines():
      line = line.strip()
      
      if not line: continue # skip blank lines
      
      if not " " in line:
        raise TypeError("Malformed line: %s" % line)
      
      path, timestamp = line.rsplit(" ", 1)
      
      if not os.path.isabs(path):
        raise TypeError("'%s' is not an absolute path" % path)
      elif not timestamp.isdigit():
        raise TypeError("'%s' is not an integer timestamp" % timestamp)
      
      processed_files[path] = int(timestamp)
  
  return processed_files

def save_processed_files(processed_files, path):
  """
  Persists a dictionary of 'path => last modified timestamp' mappings (as
  provided by the DescriptorReader's get_processed_files() method) so that they
  can be loaded later and applied to another DescriptorReader.
  
  Arguments:
    processed_files (dict) - 'path => last modified' mappings
    path (str)             - location to save the processed files dictionary to
  
  Raises:
    IOError if unable to write to the file
    TypeError if processed_files is of the wrong type
  """
  
  # makes the parent directory if it doesn't already exist
  try:
    path_dir = os.path.dirname(path)
    if not os.path.exists(path_dir): os.makedirs(path_dir)
  except OSError, exc: raise IOError(exc)
  
  with open(path, "w") as output_file:
    for path, timestamp in processed_files.items():
      if not os.path.isabs(path):
        raise TypeError("Only absolute paths are acceptable: %s" % path)
      
      output_file.write("%s %i\n" % (path, timestamp))

class DescriptorReader(threading.Thread):
  """
  Iterator for the descriptor data on the local file system. This can process
  text files, tarball archives (gzip or bzip2), or recurse directories.
  
  Arguments:
    targets (list)      - paths for files or directories to be read from
    follow_links (bool) - determines if we'll follow symlinks when transversing
                          directories
  """
  
  def __init__(self, targets, follow_links = False):
    threading.Thread.__init__(self, name="Descriptor Reader")
    self.setDaemon(True)
    
    self._targets = targets
    self._follow_links = follow_links
    self._skip_listeners = []
    self._processed_files = {}
    
    self._iter_lock = threading.RLock()
    self._iter_notice = threading.Event()
    self._is_reading = threading.Event()
    self._is_stopped = threading.Event()
    
    # descriptors that we have read, but not yet provided to the caller
    self._unreturned_descriptors = Queue.Queue()
  
  def get_processed_files(self):
    """
    For each file that we have read descriptor data from this provides a
    mapping of the form...
    
    absolute path (str) => last modified unix timestamp (int)
    
    This includes entries set through the set_processed_files() method.
    
    Returns:
      dict with the paths and unix timestamp for the last modified times of the
      files we have processed
    """
    
    return dict(self._processed_files)
  
  def set_processed_files(self, processed_files):
    """
    Sets the listing of the files we have processed. Most often this is useful
    as a method for pre-populating the listing of descriptor files that we have
    seen.
    
    Arguments:
      processed_files (dict) - mapping of absolute paths (str) to unix
                               timestamps for the last modified time (int)
    """
    
    self._processed_files = dict(processed_files)
  
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
    
    self._skip_listeners.append(listener)
  
  def stop(self):
    """
    Stops further reading of descriptor files.
    """
    
    self._is_stopped.set()
    self._iter_notice.set()
  
  def run(self):
    self._is_reading.set()
    remaining_files = list(self._targets)
    
    while remaining_files and not self._is_stopped.isSet():
      target = remaining_files.pop(0)
      if not os.path.exists(target): continue
      
      if os.path.isdir(target):
        # adds all of the files that it contains
        for root, _, files in os.walk(target, followlinks = self._follow_links):
          for filename in files:
            remaining_files.append(os.path.join(root, filename))
          
          # this can take a while if, say, we're including the root directory
          if self._is_stopped.isSet(): break
      else:
        # This is a file. Register it's last modified timestamp and check if
        # it's a file that we should skip.
        
        last_modified = os.stat(target).st_mtime
        last_used = self._processed_files.get(target)
        
        if last_used and last_used >= last_modified:
          continue
        else:
          self._processed_files[target] = last_modified
        
        # The mimetypes module only checks the file extension. To actually
        # check the content (like the 'file' command) we'd need something like
        # pymagic (https://github.com/cloudburst/pymagic).
        
        target_type = mimetypes.guess_type(target)
        
        if target_type[0] in (None, 'text/plain'):
          # if either a '.txt' or unknown type then try to process it as a
          # descriptor file
          
          with open(target) as target_file:
            # TODO: replace with actual descriptor parsing when we have it
            # TODO: impement skip listening
            self._unreturned_descriptors.put(target_file.read())
            self._iter_notice.set()
        elif target_type[0] == 'application/x-tar':
          if target_type[1] == 'gzip':
            pass # TODO: implement
          elif target_type[1] == 'bzip2':
            pass # TODO: implement
    
    self._is_reading.clear()
    self._iter_notice.set()
  
  def __iter__(self):
    with self._iter_lock:
      while not self._is_stopped.isSet():
        try:
          yield self._unreturned_descriptors.get_nowait()
        except Queue.Empty:
          # if we've finished and there aren't any descriptors then we're done
          if not self._is_reading.isSet(): break
          
          self._iter_notice.wait()
          self._iter_notice.clear()
  
  def _notify_skip_listener(self, path, exception):
    for listener in self.skip_listeners:
      listener(path, exception)
  
  def __enter__(self):
    self.start()
  
  def __exit__(self, type, value, traceback):
    self.stop()
    self.join()

