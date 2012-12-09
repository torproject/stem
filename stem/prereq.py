"""
Checks for stem dependencies. We require python 2.5 or greater (in the 2.x
series). Other requirements for complete functionality are...

* Python 2.6

  * os.walk's followlinks argument

* rsa module

  * validating descriptor signature integrity

::

  check_requirements - checks for minimum requirements for running stem
  
  is_python_26 - checks if python 2.6 or later is available
  is_python_27 - checks if python 2.7 or later is available
  
  is_rsa_available - checks if the rsa module is available
"""

import sys

from stem.util import log

IS_CRYPTO_AVAILABLE = None

def check_requirements():
  """
  Checks that we meet the minimum requirements to run stem. If we don't then
  this raises an ImportError with the issue.
  
  :raises: ImportError with the problem if we don't meet stem's requirements
  """
  
  major_version, minor_version = sys.version_info[0:2]
  
  if major_version > 2:
    raise ImportError("stem isn't compatible beyond the python 2.x series")
  elif major_version < 2 or minor_version < 5:
    raise ImportError("stem requires python version 2.5 or greater")

def is_python_26():
  """
  Checks if we're in the 2.6 - 2.x range.
  
  :returns: bool that is True if we meet this requirement and False otherwise
  """
  
  return _check_version(6)

def is_python_27():
  """
  Checks if we're in the 2.7 - 2.x range.
  
  :returns: bool that is True if we meet this requirement and False otherwise
  """
  
  return _check_version(7)

def is_crypto_available():
  global IS_CRYPTO_AVAILABLE
  
  if IS_CRYPTO_AVAILABLE is None:
    try:
      from Crypto.PublicKey import RSA
      from Crypto.Util import asn1
      from Crypto.Util.number import long_to_bytes
      IS_CRYPTO_AVAILABLE = True
    except ImportError:
      IS_CRYPTO_AVAILABLE = False
      
      # the code that verifies relay descriptor signatures uses the python-crypto library
      msg = "Unable to import the crypto module. Because of this we'll be unable to verify descriptor signature integrity."
      log.log_once("stem.prereq.is_crypto_available", log.INFO, msg)
  
  return IS_CRYPTO_AVAILABLE

def _check_version(minor_req):
  major_version, minor_version = sys.version_info[0:2]
  
  if major_version > 2:
    return False
  elif major_version < 2 or minor_version < minor_req:
    return False
  
  return True

