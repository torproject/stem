"""
Helper functions for creating mock objects and monkey patching to help with
testing. With python's builtin unit testing framework the setUp and test
functions set up mocking, which is then reverted in the tearDown method by
calling :func:`test.mocking.revert_mocking`.

::

  mock - replaces a function with an alternative implementation
  revert_mocking - reverts any changes made by the mock function
  get_real_function - provides the non-mocked version of a function
  
  Mocking Functions
    no_op           - does nothing
    return_value    - returns a given value
    return_true     - returns True
    return_false    - returns False
    return_none     - returns None
    raise_exception - raises an exception when called
  
  Instance Constructors
    get_message               - stem.socket.ControlMessage
    get_protocolinfo_response - stem.response.protocolinfo.ProtocolInfoResponse
"""

import inspect
import itertools
import StringIO
import __builtin__

import stem.response
import stem.socket

# Once we've mocked a function we can't rely on its __module__ or __name__
# attributes, so instead we associate a unique 'mock_id' attribute that maps
# back to the original attributes.

MOCK_ID = itertools.count(0)

# mock_id => (module, function_name, original_function)

MOCK_STATE = {}

BUILTIN_TYPE = type(open)

def no_op():
  def _no_op(*args): pass
  return _no_op

def return_value(value):
  def _return_value(*args): return value
  return _return_value

def return_true(): return return_value(True)
def return_false(): return return_value(False)
def return_none(): return return_value(None)

def raise_exception(exception):
  def _raise(*args): raise exception
  return _raise

def support_with(obj):
  """
  Provides no-op support for the 'with' keyword, adding __enter__ and __exit__
  methods to the object. The __enter__ provides the object itself and __exit__
  does nothing.
  
  :param object obj: object to support the 'with' keyword
  """
  
  obj.__dict__["__enter__"] = return_value(obj)
  obj.__dict__["__exit__"] = no_op()

def mock(target, mock_call, target_module=None):
  """
  Mocks the given function, saving the initial implementation so it can be
  reverted later.
  
  :param function target: function to be mocked
  :param functor mock_call: mocking to replace the function with
  """
  
  if hasattr(target, "__dict__") and "mock_id" in target.__dict__:
    # we're overriding an already mocked function
    mocking_id = target.__dict__["mock_id"]
    target_module, target_function, _ = MOCK_STATE[mocking_id]
  else:
    # this is a new mocking, save the original state
    mocking_id = MOCK_ID.next()
    target_module = target_module or inspect.getmodule(target)
    target_function = target.__name__
    MOCK_STATE[mocking_id] = (target_module, target_function, target)
  
  mock_wrapper = lambda *args: mock_call(*args)
  mock_wrapper.__dict__["mock_id"] = mocking_id
  
  # mocks the function with this wrapper
  if hasattr(target, "__dict__"):
    target_module.__dict__[target_function] = mock_wrapper
  else:
    setattr(target_module, target.__name__, mock_call)

def mock_method(target_class, method_name, mock_call):
  """
  Mocks the given class method in a similar fasion as what mock() does for
  functions.
  
  :param class target_class: class with the method we want to mock
  :param str method_name: name of the method to be mocked
  :param functor mock_call: mocking to replace the method with
  """
  
  # Ideally callers could call us with just the method, for instance like...
  #   mock_method(MyClass.foo, mocking.return_true())
  #
  # However, while classes reference the methods they have the methods
  # themselves don't reference the class. This is unfortunate because it means
  # that we need to know both the class and method we're replacing.
  
  target_method = target_class.__dict__[method_name]
  
  if "mock_id" in target_method.__dict__:
    # we're overriding an already mocked method
    mocking_id = target_method.mock_id
    _, target_method, _ = MOCK_STATE[mocking_id]
  else:
    # this is a new mocking, save the original state
    mocking_id = MOCK_ID.next()
    MOCK_STATE[mocking_id] = (target_class, method_name, target_method)
  
  mock_wrapper = lambda *args: mock_call(*args)
  mock_wrapper.__dict__["mock_id"] = mocking_id
  
  # mocks the function with this wrapper
  target_class.__dict__[method_name] = mock_wrapper

def revert_mocking():
  """
  Reverts any mocking done by this function.
  """
  
  # Reverting mocks in reverse order. If we properly reuse mock_ids then this
  # shouldn't matter, but might as well be safe.
  
  mock_ids = MOCK_STATE.keys()
  mock_ids.sort()
  mock_ids.reverse()
  
  for mock_id in mock_ids:
    module, function, impl = MOCK_STATE[mock_id]
    
    if module == __builtin__:
      setattr(__builtin__, function, impl)
    else:
      module.__dict__[function] = impl
    
    del MOCK_STATE[mock_id]
  
  MOCK_STATE.clear()

def get_real_function(function):
  """
  Provides the original, non-mocked implementation for a function or method.
  This simply returns the current implementation if it isn't being mocked.
  
  :param function function: function to look up the original implementation of
  
  :returns: original implementation of the function
  """
  
  if "mock_id" in function.__dict__:
    mocking_id = function.__dict__["mock_id"]
    return MOCK_STATE[mocking_id][2]
  else:
    return function

def get_message(content, reformat = True):
  """
  Provides a ControlMessage with content modified to be parsable. This makes
  the following changes unless 'reformat' is false...
  
  * ensures the content ends with a newline
  * newlines are replaced with a carrage return and newline pair
  
  :param str content: base content for the controller message
  :param str reformat: modifies content to be more accomidateing to being parsed
  
  :returns: stem.socket.ControlMessage instance
  """
  
  if reformat:
    if not content.endswith("\n"): content += "\n"
    content = content.replace("\n", "\r\n")
  
  return stem.socket.recv_message(StringIO.StringIO(content))

def get_protocolinfo_response(**attributes):
  """
  Provides a ProtocolInfoResponse, customized with the given attributes. The
  base instance is minimal, with its version set to one and everything else
  left with the default.
  
  :param dict attributes: attributes to customize the response with
  
  :returns: stem.response.protocolinfo.ProtocolInfoResponse instance
  """
  
  protocolinfo_response = get_message("250-PROTOCOLINFO 1\n250 OK")
  stem.response.convert("PROTOCOLINFO", protocolinfo_response)
  
  for attr in attributes:
    protocolinfo_response.__dict__[attr] = attributes[attr]
  
  return protocolinfo_response

