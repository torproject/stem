"""
Helper functions for creating mock objects and monkey patching to help with
testing.
"""

import inspect
import itertools

# Once we've mocked a function we can't rely on its __module__ or __name__
# attributes, so instead we associate a unique 'mock_id' attribute that maps
# back to the original attributes.

MOCK_ID = itertools.count(0)

# mock_id => (module, function_name, original_function)

MOCK_STATE = {}

def no_op():
  def _no_op(*args): pass
  return _no_op

def return_value(value):
  def _return_value(*args): return value
  return _return_value

def return_true(): return return_value(True)
def return_false(): return return_value(False)
def return_none(): return return_value(None)

def mock(target, mock_call):
  """
  Mocks the given function, saving the initial implementation so it can be
  reverted later.
  
  Arguments:
    target (function)   - function to be mocked
    mock_call (functor) - mocking to replace the function with
  """
  
  if "mock_id" in target.__dict__:
    # we're overriding an already mocked function
    mocking_id = target.__dict__["mock_id"]
    target_module, target_function, _ = MOCK_STATE[mocking_id]
  else:
    # this is a new mocking, save the original state
    mocking_id = MOCK_ID.next()
    target_module = inspect.getmodule(target)
    target_function = target.__name__
    MOCK_STATE[mocking_id] = (target_module, target_function, target)
  
  mock_wrapper = lambda *args: mock_call(*args)
  mock_wrapper.__dict__["mock_id"] = mocking_id
  
  # mocks the function with this wrapper
  target_module.__dict__[target_function] = mock_wrapper

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
    module.__dict__[function] = impl
  
  MOCK_STATE.clear()

