"""
Helper functions for creating mock objects and monkey patching to help with
testing. With python's builtin unit testing framework the setUp and test
functions set up mocking, which is then reverted in the tearDown method by
calling :func:`test.mocking.revert_mocking`.

::

  mock - replaces a function with an alternative implementation
  mock_method - replaces a method with an alternative implementation
  revert_mocking - reverts any changes made by the mock function
  get_real_function - provides the non-mocked version of a function
  get_all_combinations - provides all combinations of attributes
  support_with - makes object be compatible for use via the 'with' keyword
  get_object - get an arbitrary mock object of any class
  
  Mocking Functions
    no_op           - does nothing
    return_value    - returns a given value
    return_true     - returns True
    return_false    - returns False
    return_none     - returns None
    return_for_args - return based on the input arguments
    raise_exception - raises an exception when called
  
  Instance Constructors
    get_message                     - stem.socket.ControlMessage
    get_protocolinfo_response       - stem.response.protocolinfo.ProtocolInfoResponse
    
    stem.descriptor.server_descriptor
      get_relay_server_descriptor  - RelayDescriptor
      get_bridge_server_descriptor - BridgeDescriptor
    
    stem.descriptor.extrainfo_descriptor
      get_relay_extrainfo_descriptor  - RelayExtraInfoDescriptor
      get_bridge_extrainfo_descriptor - BridgeExtraInfoDescriptor
    
    stem.descriptor.networkstatus
      get_directory_authority        - DirectoryAuthority
      get_key_certificate            - KeyCertificate
      get_network_status_document_v2 - NetworkStatusDocumentV2
      get_network_status_document_v3 - NetworkStatusDocumentV3
    
    stem.descriptor.router_status_entry
      get_router_status_entry_v2       - RouterStatusEntryV2
      get_router_status_entry_v3       - RouterStatusEntryV3
      get_router_status_entry_micro_v3 - RouterStatusEntryMicroV3
"""

import base64
import hashlib
import inspect
import itertools
import StringIO
import __builtin__

import stem.descriptor.extrainfo_descriptor
import stem.descriptor.networkstatus
import stem.descriptor.router_status_entry
import stem.descriptor.server_descriptor
import stem.response
import stem.socket

# Once we've mocked a function we can't rely on its __module__ or __name__
# attributes, so instead we associate a unique 'mock_id' attribute that maps
# back to the original attributes.

MOCK_ID = itertools.count(0)

# mock_id => (module, function_name, original_function)

MOCK_STATE = {}

BUILTIN_TYPE = type(open)

CRYPTO_BLOB = """
MIGJAoGBAJv5IIWQ+WDWYUdyA/0L8qbIkEVH/cwryZWoIaPAzINfrw1WfNZGtBmg
skFtXhOHHqTRN4GPPrZsAIUOQGzQtGb66IQgT4tO/pj+P6QmSCCdTfhvGfgTCsC+
WPi4Fl2qryzTb3QO5r5x7T8OsG2IBUET1bLQzmtbC560SYR49IvVAgMBAAE=
"""

DOC_SIG = stem.descriptor.networkstatus.DocumentSignature(
  None,
  "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4",
  "BF112F1C6D5543CFD0A32215ACABD4197B5279AD",
  "-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB)

RELAY_SERVER_HEADER = (
  ("router", "caerSidi 71.35.133.197 9001 0 0"),
  ("published", "2012-03-01 17:15:27"),
  ("bandwidth", "153600 256000 104590"),
  ("reject", "*:*"),
  ("onion-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
  ("signing-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
)

RELAY_SERVER_FOOTER = (
  ("router-signature", "\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB),
)

BRIDGE_SERVER_HEADER = (
  ("router", "Unnamed 10.45.227.253 9001 0 0"),
  ("router-digest", "006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4"),
  ("published", "2012-03-22 17:34:38"),
  ("bandwidth", "409600 819200 5120"),
  ("reject", "*:*"),
)

RELAY_EXTRAINFO_HEADER = (
  ("extra-info", "ninja B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48"),
  ("published", "2012-05-05 17:03:50"),
)

RELAY_EXTRAINFO_FOOTER = (
  ("router-signature", "\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB),
)

BRIDGE_EXTRAINFO_HEADER = (
  ("extra-info", "ec2bridgereaac65a3 1EC248422B57D9C0BD751892FE787585407479A4"),
  ("published", "2012-05-05 17:03:50"),
)

BRIDGE_EXTRAINFO_FOOTER = (
  ("router-digest", "006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4"),
)

ROUTER_STATUS_ENTRY_V2_HEADER = (
  ("r", "caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0"),
)

ROUTER_STATUS_ENTRY_V3_HEADER = (
  ("r", "caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0"),
  ("s", "Fast Named Running Stable Valid"),
)

ROUTER_STATUS_ENTRY_MICRO_V3_HEADER = (
  ("r", "Konata ARIJF2zbqirB9IwsW0mQznccWww 2012-09-24 13:40:40 69.64.48.168 9001 9030"),
  ("m", "aiUklwBrua82obG5AsTX+iEpkjQA2+AQHxZ7GwMfY70"),
  ("s", "Fast Guard HSDir Named Running Stable V2Dir Valid"),
)

AUTHORITY_HEADER = (
  ("dir-source", "turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090"),
  ("contact", "Mike Perry <email>"),
)

KEY_CERTIFICATE_HEADER = (
  ("dir-key-certificate-version", "3"),
  ("fingerprint", "27B6B5996C426270A5C95488AA5BCEB6BCC86956"),
  ("dir-key-published", "2011-11-28 21:51:04"),
  ("dir-key-expires", "2012-11-28 21:51:04"),
  ("dir-identity-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
  ("dir-signing-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
)

KEY_CERTIFICATE_FOOTER = (
  ("dir-key-certification", "\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB),
)

NETWORK_STATUS_DOCUMENT_HEADER_V2 = (
  ("network-status-version", "2"),
  ("dir-source", "18.244.0.114 18.244.0.114 80"),
  ("fingerprint", "719BE45DE224B607C53707D0E2143E2D423E74CF"),
  ("contact", "arma at mit dot edu"),
  ("published", "2005-12-16 00:13:46"),
  ("dir-signing-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
)

NETWORK_STATUS_DOCUMENT_FOOTER_V2 = (
  ("directory-signature", "moria2\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB),
)

NETWORK_STATUS_DOCUMENT_HEADER = (
  ("network-status-version", "3"),
  ("vote-status", "consensus"),
  ("consensus-methods", None),
  ("consensus-method", None),
  ("published", None),
  ("valid-after", "2012-09-02 22:00:00"),
  ("fresh-until", "2012-09-02 22:00:00"),
  ("valid-until", "2012-09-02 22:00:00"),
  ("voting-delay", "300 300"),
  ("client-versions", None),
  ("server-versions", None),
  ("known-flags", "Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid"),
  ("params", None),
)

NETWORK_STATUS_DOCUMENT_FOOTER = (
  ("directory-footer", ""),
  ("bandwidth-weights", None),
  ("directory-signature", "%s %s\n%s" % (DOC_SIG.identity, DOC_SIG.key_digest, DOC_SIG.signature)),
)

def no_op():
  def _no_op(*args): pass
  return _no_op

def return_value(value):
  def _return_value(*args): return value
  return _return_value

def return_true(): return return_value(True)
def return_false(): return return_value(False)
def return_none(): return return_value(None)

def return_for_args(args_to_return_value, default = None, is_method = False):
  """
  Returns a value if the arguments to it match something in a given
  'argument => return value' mapping. Otherwise, a default function
  is called with the arguments.
  
  The mapped argument is a tuple (not a list) of parameters to a function or
  method. Positional arguments must be in the order used to call the mocked
  function, and keyword arguments must be strings of the form 'k=v'. Keyword
  arguments **must** appear in alphabetical order. For example...
  
  ::
  
    mocking.mock("get_answer", mocking.return_for_args({
      ("breakfast_menu",): "spam",
      ("lunch_menu",): "eggs and spam",
      (42,): ["life", "universe", "everything"],
    }))
    
    mocking.mock("align_text", mocking.return_for_args({
      ("Stem", "alignment=left", "size=10"):   "Stem      ",
      ("Stem", "alignment=center", "size=10"): "   Stem   ",
      ("Stem", "alignment=right", "size=10"):  "      Stem",
    }))
    
    mocking.mock_method(Controller, "new_circuit", mocking.return_for_args({
      (): "1",
      ("path=['718BCEA286B531757ACAFF93AE04910EA73DE617', " + \
        "'30BAB8EE7606CBD12F3CC269AE976E0153E7A58D', " + \
        "'2765D8A8C4BBA3F89585A9FFE0E8575615880BEB']",): "2"
      ("path=['1A', '2B', '3C']", "purpose=controller"): "3"
    }, is_method = True))
  
  :param dict args_to_return_value: mapping of arguments to the value we should provide
  :param functor default: returns the value of this function if the args don't
    match something that we have, we raise a ValueError by default
  :param bool is_method: handles this like a method, removing the 'self'
    reference
  """
  
  def _return_value(*args, **kwargs):
    # strip off the 'self' if we're mocking a method
    if args and is_method:
      args = args[1:] if len(args) > 2 else [args[1]]
    
    if kwargs:
      args.extend(["%s=%s" % (k, kwargs[k]) for k in sorted(kwargs.keys())])
    
    args = tuple(args)
    
    if args in args_to_return_value:
      return args_to_return_value[args]
    elif default is None:
      arg_label = ", ".join([str(v) for v in args])
      arg_keys = ", ".join([str(v) for v in args_to_return_value.keys()])
      raise ValueError("Unrecognized argument sent for return_for_args(). Got '%s' but we only recognize '%s'." % (arg_label, arg_keys))
    else:
      return default(args)
  
  return _return_value

def raise_exception(exception):
  def _raise(*args): raise exception
  return _raise

def support_with(obj):
  """
  Provides no-op support for the 'with' keyword, adding __enter__ and __exit__
  methods to the object. The __enter__ provides the object itself and __exit__
  does nothing.
  
  :param object obj: object to support the 'with' keyword
  
  :returns: input object
  """
  
  obj.__dict__["__enter__"] = return_value(obj)
  obj.__dict__["__exit__"] = no_op()
  return obj

def mock(target, mock_call, target_module=None):
  """
  Mocks the given function, saving the initial implementation so it can be
  reverted later.
  
  The target_module only needs to be set if the results of
  'inspect.getmodule(target)' doesn't match the module that we want to mock
  (for instance, the 'os' module provides the platform module that it wraps
  like 'postix', which won't work).
  
  :param function target: function to be mocked
  :param functor mock_call: mocking to replace the function with
  :param module target_module: module that this is mocking, this defaults to the inspected value
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
  
  mock_wrapper = lambda *args, **kwargs: mock_call(*args, **kwargs)
  mock_wrapper.__dict__["mock_id"] = mocking_id
  
  # mocks the function with this wrapper
  if hasattr(target, "__dict__"):
    target_module.__dict__[target_function] = mock_wrapper
  else:
    setattr(target_module, target.__name__, mock_call)

def mock_method(target_class, method_name, mock_call):
  """
  Mocks the given method in target_class in a similar fashion as mock()
  does for functions. For instance...
  
  ::
  
    >>> mock_method(stem.control.Controller, "is_feature_enabled", mocking.return_true())
    >>> controller.is_feature_enabled("VERBOSE_EVENTS")
    True
    
  ::
  
  "VERBOSE_EVENTS" does not exist and can never be True, but the mocked
  "is_feature_enabled" will always return True, regardless.
  
  :param class target_class: class with the method we want to mock
  :param str method_name: name of the method to be mocked
  :param functor mock_call: mocking to replace the method
  """
  
  # Ideally callers could call us with just the method, for instance like...
  #   mock_method(MyClass.foo, mocking.return_true())
  #
  # However, while classes reference the methods they have the methods
  # themselves don't reference the class. This is unfortunate because it means
  # that we need to know both the class and method we're replacing.
  
  target_method = getattr(target_class, method_name)
  
  if "mock_id" in target_method.__dict__:
    # we're overriding an already mocked method
    mocking_id = target_method.mock_id
    _, target_method, _ = MOCK_STATE[mocking_id]
  else:
    # this is a new mocking, save the original state
    mocking_id = MOCK_ID.next()
    MOCK_STATE[mocking_id] = (target_class, method_name, target_method)
  
  mock_wrapper = lambda *args, **kwargs: mock_call(*args, **kwargs)
  setattr(mock_wrapper, "mock_id", mocking_id)
  
  # mocks the function with this wrapper
  setattr(target_class, method_name, mock_wrapper)

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
      setattr(module, function, impl)
    
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

def get_all_combinations(attr, include_empty = False):
  """
  Provides an iterator for all combinations of a set of attributes. For
  instance...
  
  ::
  
    >>> list(test.mocking.get_all_combinations(["a", "b", "c"]))
    [('a',), ('b',), ('c',), ('a', 'b'), ('a', 'c'), ('b', 'c'), ('a', 'b', 'c')]
  
  :param list attr: attributes to provide combinations for
  :param bool include_empty: includes an entry with zero items if True
  :returns: iterator for all combinations
  """
  
  # Makes an itertools.product() call for 'i' copies of attr...
  #
  # * itertools.product(attr) => all one-element combinations
  # * itertools.product(attr, attr) => all two-element combinations
  # * ... etc
  
  if include_empty: yield ()
  
  seen = set()
  for index in xrange(1, len(attr) + 1):
    product_arg = [attr for _ in xrange(index)]
    
    for item in itertools.product(*product_arg):
      # deduplicate, sort, and only provide if we haven't seen it yet
      item = tuple(sorted(set(item)))
      
      if not item in seen:
        seen.add(item)
        yield item

def get_object(object_class, methods = None):
  """
  Provides a mock instance of an arbitrary class. Its methods are mocked with
  the given replacements, and calling any others will result in an exception.
  
  :param class object_class: class that we're making an instance of
  :param dict methods: mapping of method names to their mocked implementation
  
  :returns: stem.control.Controller instance
  """
  
  if methods is None:
    methods = {}
  
  mock_methods = {}
  
  for method_name in dir(object_class):
    if method_name in methods:
      mock_methods[method_name] = methods[method_name]
    elif method_name.startswith('__') and method_name.endswith('__'):
      pass # messing with most private methods makes for a broken mock object
    else:
      mock_methods[method_name] = raise_exception(ValueError("Unexpected call of '%s' on a mock object" % method_name))
  
  # makes it so our constructor won't need any arguments
  mock_methods['__init__'] = no_op()
  
  mock_class = type('MockClass', (object_class,), mock_methods)
  
  return mock_class()

def get_message(content, reformat = True):
  """
  Provides a ControlMessage with content modified to be parsable. This makes
  the following changes unless 'reformat' is false...
  
  * ensures the content ends with a newline
  * newlines are replaced with a carriage return and newline pair
  
  :param str content: base content for the controller message
  :param str reformat: modifies content to be more accommodating to being parsed
  
  :returns: stem.response.ControlMessage instance
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

def _get_descriptor_content(attr = None, exclude = (), header_template = (), footer_template = ()):
  """
  Constructs a minimal descriptor with the given attributes. The content we
  provide back is of the form...
  
  * header_template (with matching attr filled in)
  * unused attr entries
  * footer_template (with matching attr filled in)
  
  So for instance...
  
  ::
  
    get_descriptor_content(
      attr = {'nickname': 'caerSidi', 'contact': 'atagar'},
      header_template = (
        ('nickname', 'foobar'),
        ('fingerprint', '12345'),
      ),
    )
  
  ... would result in...
  
  ::
  
    nickname caerSidi
    fingerprint 12345
    contact atagar
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param tuple header_template: key/value pairs for mandatory fields before unrecognized content
  :param tuple footer_template: key/value pairs for mandatory fields after unrecognized content
  
  :returns: str with the requested descriptor content
  """
  
  header_content, footer_content = [], []
  if attr is None: attr = {}
  attr = dict(attr) # shallow copy since we're destructive
  
  for content, template in ((header_content, header_template),
                           (footer_content, footer_template)):
    for keyword, value in template:
      if keyword in exclude: continue
      elif keyword in attr:
        value = attr[keyword]
        del attr[keyword]
      
      if value is None: continue
      elif value == "":
        content.append(keyword)
      elif keyword == "onion-key" or keyword == "signing-key" or keyword == "router-signature":
        content.append("%s%s" % (keyword, value))
      else:
        content.append("%s %s" % (keyword, value))
  
  remainder = []
  
  for k, v in attr.items():
    if v: remainder.append("%s %s" % (k, v))
    else: remainder.append(k)
  
  return "\n".join(header_content + remainder + footer_content)

def get_relay_server_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.server_descriptor.RelayDescriptor
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: RelayDescriptor for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, RELAY_SERVER_HEADER, RELAY_SERVER_FOOTER)
  
  if content:
    return desc_content
  else:
    desc_content = sign_descriptor_content(desc_content)
    return stem.descriptor.server_descriptor.RelayDescriptor(desc_content, validate = True)

def get_bridge_server_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.server_descriptor.BridgeDescriptor
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: BridgeDescriptor for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, BRIDGE_SERVER_HEADER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.server_descriptor.BridgeDescriptor(desc_content, validate = True)

def get_relay_extrainfo_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: RelayExtraInfoDescriptor for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, RELAY_EXTRAINFO_HEADER, RELAY_EXTRAINFO_FOOTER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor(desc_content, validate = True)

def get_bridge_extrainfo_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: BridgeExtraInfoDescriptor for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, BRIDGE_EXTRAINFO_HEADER, BRIDGE_EXTRAINFO_FOOTER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor(desc_content, validate = True)

def get_router_status_entry_v2(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.router_status_entry.RouterStatusEntryV2
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: RouterStatusEntryV2 for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, ROUTER_STATUS_ENTRY_V2_HEADER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.router_status_entry.RouterStatusEntryV2(desc_content, validate = True)

def get_router_status_entry_v3(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.router_status_entry.RouterStatusEntryV3
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: RouterStatusEntryV3 for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, ROUTER_STATUS_ENTRY_V3_HEADER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.router_status_entry.RouterStatusEntryV3(desc_content, validate = True)

def get_router_status_entry_micro_v3(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.router_status_entry.RouterStatusEntryMicroV3
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: RouterStatusEntryMicroV3 for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, ROUTER_STATUS_ENTRY_MICRO_V3_HEADER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.router_status_entry.RouterStatusEntryMicroV3(desc_content, validate = True)

def get_directory_authority(attr = None, exclude = (), is_vote = False, content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.DirectoryAuthority
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool is_vote: True if this is for a vote, False if it's for a consensus
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: DirectoryAuthority for the requested descriptor content
  """
  
  if attr is None:
    attr = {}
  
  if not is_vote:
    # entries from a consensus also have a mandatory 'vote-digest' field
    if not ('vote-digest' in attr or (exclude and 'vote-digest' in exclude)):
      attr['vote-digest'] = '0B6D1E9A300B895AA2D0B427F92917B6995C3C1C'
  
  desc_content = _get_descriptor_content(attr, exclude, AUTHORITY_HEADER)
  
  if is_vote:
    desc_content += "\n" + str(get_key_certificate())
  
  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.DirectoryAuthority(desc_content, validate = True, is_vote = is_vote)

def get_key_certificate(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.KeyCertificate
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: KeyCertificate for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, KEY_CERTIFICATE_HEADER, KEY_CERTIFICATE_FOOTER)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.KeyCertificate(desc_content, validate = True)

def get_network_status_document_v2(attr = None, exclude = (), routers = None, content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.NetworkStatusDocumentV2
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param list routers: router status entries to include in the document
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: NetworkStatusDocumentV2 for the requested descriptor content
  """
  
  desc_content = _get_descriptor_content(attr, exclude, NETWORK_STATUS_DOCUMENT_HEADER_V2, NETWORK_STATUS_DOCUMENT_FOOTER_V2)
  
  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.NetworkStatusDocumentV2(desc_content, validate = True)

def get_network_status_document_v3(attr = None, exclude = (), authorities = None, routers = None, content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.NetworkStatusDocumentV3
  
  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param list authorities: directory authorities to include in the document
  :param list routers: router status entries to include in the document
  :param bool content: provides the str content of the descriptor rather than the class if True
  
  :returns: NetworkStatusDocumentV3 for the requested descriptor content
  """
  
  if attr is None:
    attr = {}
  
  # add defaults only found in a vote, consensus, or microdescriptor
  
  if attr.get("vote-status") == "vote":
    extra_defaults = {
      "consensus-methods": "1 9",
      "published": "2012-09-02 22:00:00",
    }
  else:
    extra_defaults = {
      "consensus-method": "9",
    }
  
  for k, v in extra_defaults.items():
    if not (k in attr or (exclude and k in exclude)):
      attr[k] = v
  
  desc_content = _get_descriptor_content(attr, exclude, NETWORK_STATUS_DOCUMENT_HEADER, NETWORK_STATUS_DOCUMENT_FOOTER)
  
  # inject the authorities and/or routers between the header and footer
  if authorities:
    footer_div = desc_content.find("\ndirectory-footer") + 1
    authority_content = "\n".join([str(a) for a in authorities]) + "\n"
    desc_content = desc_content[:footer_div] + authority_content + desc_content[footer_div:]
  
  if routers:
    footer_div = desc_content.find("\ndirectory-footer") + 1
    router_content = "\n".join([str(r) for r in routers]) + "\n"
    desc_content = desc_content[:footer_div] + router_content + desc_content[footer_div:]
  
  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.NetworkStatusDocumentV3(desc_content, validate = True)

def sign_descriptor_content(desc_content):
  """
  Add a valid signature to the supplied descriptor string.
  If the python-crypto library is available the function will generate a key
  pair, and use it to sign the descriptor string. Any existing fingerprint,
  signing-key or router-signature data will be overwritten.
  If crypto is unavailable the code will return the unaltered descriptor
  string.
  :param string desc_content: the descriptor string to sign
  :returns: a descriptor string, signed if crypto available, unaltered otherwise
  """
  
  if not stem.prereq.is_crypto_available():
    return desc_content
  else:
    from Crypto.PublicKey import RSA
    from Crypto.Util import asn1
    from Crypto.Util.number import long_to_bytes
    
    # generate a key
    private_key = RSA.generate(1024)
    
    # get a string representation of the public key
    seq = asn1.DerSequence()
    seq.append(private_key.n)
    seq.append(private_key.e)
    seq_as_string = seq.encode()
    public_key_string = base64.b64encode(seq_as_string)
    
    # split public key into lines 64 characters long
    public_key_string =  public_key_string [:64] + "\n" +public_key_string[64:128] +"\n" +public_key_string[128:]
    
    # generate the new signing key string
    signing_key_token = "\nsigning-key\n" # note the trailing '\n' is important here so as not to match the string elsewhere
    signing_key_token_start = "-----BEGIN RSA PUBLIC KEY-----\n"
    signing_key_token_end = "\n-----END RSA PUBLIC KEY-----\n"
    new_sk = signing_key_token+ signing_key_token_start+public_key_string+signing_key_token_end
    
    # update the descriptor string with the new signing key
    skt_start = desc_content.find(signing_key_token)
    skt_end = desc_content.find(signing_key_token_end, skt_start)
    desc_content = desc_content[:skt_start]+new_sk+ desc_content[skt_end+len(signing_key_token_end):]
    
    # generate the new fingerprint string
    key_hash = hashlib.sha1(seq_as_string).hexdigest().upper()
    grouped_fingerprint = ""
    for x in range(0, len(key_hash), 4):
      grouped_fingerprint += " " + key_hash[x:x+4]
      fingerprint_token = "\nfingerprint"
      new_fp = fingerprint_token + grouped_fingerprint
      
    # update the descriptor string with the new fingerprint
    ft_start = desc_content.find(fingerprint_token)
    if ft_start < 0:
      fingerprint_token = "\nopt fingerprint"
      ft_start = desc_content.find(fingerprint_token)
    
    # if the descriptor does not already contain a fingerprint do not add one
    if ft_start >= 0:
      ft_end = desc_content.find("\n", ft_start+1)
      desc_content = desc_content[:ft_start]+new_fp+desc_content[ft_end:]
    
    # create a temporary object to use to calculate the digest
    tempDesc = stem.descriptor.server_descriptor.RelayDescriptor(desc_content, validate=False)
    # calculate the new digest for the descriptor
    new_digest_hex = tempDesc.digest().lower()
    # remove the hex encoding
    new_digest = new_digest_hex.decode('hex')
    
    # Generate the digest buffer.
    #  block is 128 bytes in size
    #  2 bytes for the type info
    #  1 byte for the separator
    padding = ""
    for x in range(125 - len(new_digest)):
      padding += '\xFF'
      digestBuffer = '\x00\x01' + padding + '\x00' + new_digest
    
    # generate a new signature by signing the digest buffer with the private key
    (signature, ) = private_key.sign(digestBuffer, None)
    signature_as_bytes = long_to_bytes(signature, 128)
    signature_base64 = base64.b64encode(signature_as_bytes)
    signature_base64 =  signature_base64 [:64] + "\n" +signature_base64[64:128] +"\n" +signature_base64[128:]
    
    # update the descriptor string with the new signature
    router_signature_token = "\nrouter-signature\n"
    router_signature_start = "-----BEGIN SIGNATURE-----\n"
    router_signature_end = "\n-----END SIGNATURE-----\n"
    rst_start = desc_content.find(router_signature_token)
    desc_content = desc_content[:rst_start] + router_signature_token + router_signature_start + signature_base64 + router_signature_end
    
    return desc_content
