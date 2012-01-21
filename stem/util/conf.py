"""
This provides handlers for specially formatted configuration files. Entries are
expected to consist of simple key/value pairs, and anything after "#" is
stripped as a comment. Excess whitespace is trimmed and empty lines are
ignored. For instance:

  # This is my sample config
  user.name Galen
  user.password yabba1234 # here's an inline comment
  user.notes takes a fancy to pepperjack chese
  blankEntry.example

would be loaded as four entries, the last one's value being an empty string.

get_config - Singleton for getting configurations
Config - Custom configuration.
  |- load - reads a configuration file
  |- save - writes the current configuration to a file
  |- clear - empties our loaded configuration contents
  |- update - replaces mappings in a dictionary with the config's values
  |- keys - provides keys in the loaded configuration
  |- set - sets the given key/value pair
  |- unused_keys - provides keys that have never been requested
  |- get - provides the value for a given key, with type inference
  |- get_value - provides the value for a given key as a string
  |- get_str_csv - gets a value as a comma separated list of strings
  +- get_int_csv - gets a value as a comma separated list of integers
"""

import threading

import stem.util.log as log

CONFS = {}  # mapping of identifier to singleton instances of configs

# TODO: methods that will be needed if we want to allow for runtime
# customization...
#
# Config.set(key, value) - accepts any type that the get() method does,
#   updating our contents with the string conversion
#
# Config.addListener(functor) - allow other classes to have callbacks for when
#   the configuration is changed (either via load() or set())
#
# Config.save(path) - writes our current configurations, ideally merging them
#   with the file that exists there so commenting and such are preserved

def get_config(handle):
  """
  Singleton constructor for configuration file instances. If a configuration
  already exists for the handle then it's returned. Otherwise a fresh instance
  is constructed.
  
  Arguments:
    handle (str) - unique identifier used to access this config instance
  """
  
  if not handle in CONFS: CONFS[handle] = Config()
  return CONFS[handle]

class Config():
  """
  Handler for easily working with custom configurations, providing persistence
  to and from files. All operations are thread safe.
  
  Example usage:
    User has a file at '/home/atagar/myConfig' with...
      destination.ip 1.2.3.4
      destination.port blarg
      
      startup.run export PATH=$PATH:~/bin
      startup.run alias l=ls
    
    And they have a script with...
      import stem.util.conf
      
      # Configuration values we'll use in this file. These are mappings of
      # configuration keys to the default values we'll use if the user doesn't
      # have something different in their config file (or it doesn't match this
      # type).
      
      ssh_config = {"login.user": "atagar",
                    "login.password": "pepperjack_is_awesome!",
                    "destination.ip": "127.0.0.1",
                    "destination.port": 22,
                    "startup.run": []}
      
      # Makes an empty config instance with the handle of 'ssh_login'. This is
      # a singleton so other classes can fetch this same configuration from
      # this handle.
      
      user_config = stem.util.conf.get_config("ssh_login")
      
      # Loads the user's configuration file, warning if this fails.
      
      try:
        user_config.load("/home/atagar/myConfig")
      except IOError, exc:
        print "Unable to load the user's config: %s" % exc
      
      # Replaces the contents of ssh_config with the values from the user's
      # config file if...
      # - the key is present in the config file
      # - we're able to convert the configuration file's value to the same type
      #   as what's in the mapping (see the Config.get() method for how these
      #   type inferences work)
      #
      # For instance in this case the login values are left alone (because they
      # aren't in the user's config file), and the 'destination.port' is also
      # left with the value of 22 because we can't turn "blarg" into an
      # integer.
      #
      # The other values are replaced, so ssh_config now becomes...
      # {"login.user": "atagar",
      #  "login.password": "pepperjack_is_awesome!",
      #  "destination.ip": "1.2.3.4",
      #  "destination.port": 22,
      #  "startup.run": ["export PATH=$PATH:~/bin", "alias l=ls"]}
      #
      # Information for what values fail to load and why are reported to
      # 'stem.util.log'.
      
      user_config.update(ssh_config)
  """
  
  def __init__(self):
    """
    Creates a new configuration instance.
    """
    
    self._path = None        # location we last loaded from or saved to
    self._contents = {}      # configuration key/value pairs
    self._raw_contents = []  # raw contents read from configuration file
    
    # used for both _contents and _raw_contents access
    self._contents_lock = threading.RLock()
    
    # keys that have been requested (used to provide unused config contents)
    self._requested_keys = set()
  
  def load(self, path):
    """
    Reads in the contents of the given path, adding its configuration values
    to our current contents.
    
    Arguments:
      path (str) - file path to be loaded
    
    Raises:
      IOError if we fail to read the file (it doesn't exist, insufficient
      permissions, etc)
    """
    
    with open(path, "r") as config_file:
      read_contents = config_file.readlines()
    
    self._contents_lock.acquire()
    self._raw_contents = read_contents
    
    for line in self._raw_contents:
      # strips any commenting or excess whitespace
      comment_start = line.find("#")
      if comment_start != -1: line = line[:comment_start]
      line = line.strip()
      
      # parse the key/value pair
      if line:
        try:
          key, value = line.split(" ", 1)
          value = value.strip()
        except ValueError:
          log.debug("Config entry '%s' is expected to be of the format 'Key Value', defaulting to '%s' -> ''" % (line, line))
          key, value = line, ""
        
        self.set(key, value)
    
    self._path = path
    self._contents_lock.release()
  
  def save(self):
    self._contents_lock.acquire()
    
    config_keys = self.keys()
    config_keys.sort()
    
    with open(path, 'w') as f:
      for entry_key in config_keys:
        for entry_value in self.get_value(entry_key, multiple = True):
          f.write('%s %s\n' % (entry_key, entry_value))
    
    self._contents_lock.release()
  
  def clear(self):
    """
    Drops the configuration contents and reverts back to a blank, unloaded
    state.
    """
    
    self._contents_lock.acquire()
    self._path = None
    self._contents.clear()
    self._raw_contents = []
    self._requested_keys = set()
    self._contents_lock.release()
  
  def update(self, conf_mappings, limits = None):
    """
    This takes a dictionary of 'config_key => default_value' mappings and
    changes the values to reflect our current configuration. This will leave
    the previous values alone if...
    
    a. we don't have a value for that config_key
    b. we can't convert our value to be the same type as the default_value
    
    For more information about how we convert types see our get() method.
    
    Arguments:
      conf_mappings (dict) - configuration key/value mappings to be revised
      limits (dict)        - mappings of limits on numeric values, expected to
                             be of the form "configKey -> min" or "configKey ->
                             (min, max)"
    """
    
    if limits == None: limits = {}
    
    for entry in conf_mappings.keys():
      val = self.get(entry, conf_mappings[entry])
      
      # if this was a numeric value then apply constraints
      if entry in limits and (isinstance(val, int) or isinstance(val, float)):
        if isinstance(limits[entry], tuple):
          val = max(val, limits[entry][0])
          val = min(val, limits[entry][1])
        else: val = max(val, limits[entry])
      
      # only use this value if it wouldn't change the type of the mapping (this
      # will only fail if the type isn't either a string or one of the types
      # recognized by the get method)
      
      if type(val) == type(conf_mappings[entry]):
        conf_mappings[entry] = val
  
  def keys(self):
    """
    Provides all keys in the currently loaded configuration.
    
    Returns:
      list if strings for the configuration keys we've loaded
    """
    
    return self._contents.keys()
  
  def unused_keys(self):
    """
    Provides the configuration keys that have never been provided to a caller
    via the get, get_value, or update methods.
    
    Returns:
      set of configuration keys we've loaded but have never been requested
    """
    
    return set(self.get_keys()).difference(self._requested_keys)
  
  def set(self, key, value):
    """
    Appends the given key/value configuration mapping, behaving the same as if
    we'd loaded this from a configuration file.
    
    Arguments:
      key (str)   - key for the configuration mapping
      value (str) - value we're setting the mapping to
    """
    
    if key in self._contents: self._contents[key].append(value)
    else: self._contents[key] = [value]
  
  def get(self, key, default = None):
    """
    Fetches the given configuration, using the key and default value to
    determine the type it should be. Recognized inferences are:
    
    - default is a boolean => boolean
      * values are case insensitive
      * provides the default if the value isn't "true" or "false"
    
    - default is an integer => int
      * provides the default if the value can't be converted to an int
    
    - default is a float => float
      * provides the default if the value can't be converted to a float
    
    - default is a list => list
      * string contents for all configuration values with this key
    
    - default is a tuple => tuple
      * string contents for all configuration values with this key
    
    - default is a dictionary => dict
      * values without "=>" in them are ignored
      * values are split into key/value pairs on "=>" with extra whitespace
        stripped
    
    Arguments:
      key (str)        - config setting to be fetched
      default (object) - value provided if no such key exists or fails to be
                         converted
    
    Returns:
      given configuration value with its type inferred with the above rules
    """
    
    is_multivalue = type(default) in (list, tuple, dict)
    val = self.get_value(key, default, is_multivalue)
    if val == default: return val # don't try to infer undefined values
    
    if isinstance(default, bool):
      if val.lower() == "true": val = True
      elif val.lower() == "false": val = False
      else:
        log.debug("Config entry '%s' is expected to be a boolean, defaulting to '%s'" % (key, str(default)))
        val = default
    elif isinstance(default, int):
      try: val = int(val)
      except ValueError:
        log.debug("Config entry '%s' is expected to be an integer, defaulting to '%i'" % (key, default))
        val = default
    elif isinstance(default, float):
      try: val = float(val)
      except ValueError:
        log.debug("Config entry '%s' is expected to be a float, defaulting to '%f'" % (key, default))
        val = default
    elif isinstance(default, list):
      pass # nothing special to do (already a list)
    elif isinstance(default, tuple):
      val = tuple(val)
    elif isinstance(default, dict):
      valMap = {}
      for entry in val:
        if "=>" in entry:
          entryKey, entryVal = entry.split("=>", 1)
          valMap[entryKey.strip()] = entryVal.strip()
        else:
          log.debug("Ignoring invalid %s config entry (expected a mapping, but \"%s\" was missing \"=>\")" % (key, entry))
      val = valMap
    
    return val
  
  def get_value(self, key, default = None, multiple = False):
    """
    This provides the current value associated with a given key.
    
    Arguments:
      key (str)        - config setting to be fetched
      default (object) - value provided if no such key exists
      multiple (bool)  - provides back a list of all values if true, otherwise
                         this returns the last loaded configuration value
    
    Returns:
      string or list of string configuration values associated with the given
      key, providing the default if no such key exists
    """
    
    self._contents_lock.acquire()
    
    if key in self._contents:
      val = self._contents[key]
      if not multiple: val = val[-1]
      self._requested_keys.add(key)
    else:
      message_id = "stem.util.conf.missing_config_key_%s" % key
      log.log_once(message_id, log.TRACE, "config entry '%s' not found, defaulting to '%s'" % (key, default))
      val = default
    
    self._contents_lock.release()
    
    return val
  
  def get_str_csv(self, key, default = None, count = None, sub_key = None):
    """
    Fetches the given key as a comma separated value.
    
    Arguments:
      key (str)        - config setting to be fetched, last if multiple exists
      default (object) - value provided if no such key exists or doesn't match
                         the count
      count (int)      - if set then the default is returned when the number of
                         elements doesn't match this value
      sub_key (str)    - handle the configuration entry as a dictionary and use
                         this key within it
    
    Returns:
      list with the stripped values
    """
    
    if sub_key: conf_value = self.get(key, {}).get(sub_key)
    else: conf_value = self.get_value(key)
    
    if conf_value == None: return default
    elif not conf_value.strip(): return [] # empty string
    else:
      conf_comp = [entry.strip() for entry in conf_value.split(",")]
      
      # check if the count doesn't match
      if count != None and len(conf_comp) != count:
        msg = "Config entry '%s' is expected to be %i comma separated values" % (key, count)
        if default != None and (isinstance(default, list) or isinstance(default, tuple)):
          defaultStr = ", ".join([str(i) for i in default])
          msg += ", defaulting to '%s'" % defaultStr
        
        log.debug(msg)
        return default
      
      return conf_comp
  
  def get_int_csv(self, key, default = None, count = None, min_value = None, max_value = None, sub_key = None):
    """
    Fetches the given comma separated value, returning the default if the
    values aren't integers or don't follow the given constraints.
    
    Arguments:
      key (str)        - config setting to be fetched, last if multiple exists
      default (object) - value provided if no such key exists, doesn't match the count,
                         values aren't all integers, or doesn't match the bounds
      count (int)      - checks that the number of values matches this if set
      min_value (int)  - checks that all values are over this if set
      max_value (int)  - checks that all values are under this if set
      sub_key (str)    - handle the configuration entry as a dictionary and use
                         this key within it
    
    Returns:
      list with the stripped values
    """
    
    conf_comp = self.get_str_csv(key, default, count, sub_key)
    if conf_comp == default: return default
    
    # validates the input, setting the error_msg if there's a problem
    error_msg = None
    base_error_msg = "Config entry '%s' is expected to %%s" % key
    
    # includes our default value in the message
    if default != None and (isinstance(default, list) or isinstance(default, tuple)):
      default_str = ", ".join([str(i) for i in default])
      base_error_msg += ", defaulting to '%s'" % default_str
    
    for val in conf_comp:
      if not val.isdigit():
        error_msg = base_error_msg % "only have integer values"
        break
      else:
        if min_value != None and int(val) < min_value:
          error_msg = base_error_msg % "only have values over %i" % min_value
          break
        elif max_value != None and int(val) > max_value:
          error_msg = base_error_msg % "only have values less than %i" % max_value
          break
    
    if error_msg:
      log.debug(error_msg)
      return default
    else: return [int(val) for val in conf_comp]

