import binascii
import hashlib
import hmac
import json
import socket
import time
import urllib
import urllib2

import socks  # SockiPy module
import stem.process

SOCKS_PORT = 7000
TWITTER_API_URL = "https://api.twitter.com/1.1/statuses/user_timeline.json"
CONSUMER_KEY = ""
CONSUMER_SECRET = ""
ACCESS_TOKEN = ""
ACCESS_TOKEN_SECRET = ""

HEADER_AUTH_KEYS = ['oauth_consumer_key', 'oauth_nonce', 'oauth_signature',
  'oauth_signature_method', 'oauth_timestamp', 'oauth_token', 'oauth_version']

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
socket.socket = socks.socksocket

def oauth_signature(key_dict):
  fin_key = ""

  for key in sorted(key_dict.keys()):
    fin_key += key + "=" + key_dict[key] + "&"

  fin_key =  fin_key[:-1]
  fin_key = 'GET' + "&" + urllib.quote(TWITTER_API_URL, '') + "&" + urllib.quote(fin_key, '')
  key = urllib.quote(CONSUMER_SECRET, '') + "&" + urllib.quote(ACCESS_TOKEN_SECRET, '')
  hashed = hmac.new(key, fin_key, hashlib.sha1)
  fin_key = binascii.b2a_base64(hashed.digest())[:-1]
  return urllib.quote(fin_key, '')

def poll_twitter_feed(user_id, tweet_count):
  """
  Polls Twitter for the tweets from a given user.
  """

  key_dict = {
    'oauth_consumer_key': urllib.quote(CONSUMER_KEY, ''),
    'oauth_nonce': urllib.quote(hashlib.md5(str(time.time())).hexdigest(), ''),
    'oauth_signature_method': urllib.quote("HMAC-SHA1", ''),
    'oauth_timestamp': urllib.quote(str(int(time.time())), ''),
    'oauth_token': urllib.quote(ACCESS_TOKEN, ''),
    'oauth_version': urllib.quote('1.0', ''),
  }

  url_values = {'screen_name': user_id, 'count': str(tweet_count), 'include_rts': '1'}

  for key, value in url_values.items():
    key_dict[key] = urllib.quote(value, '')

  key_dict['oauth_signature'] = oauth_signature(key_dict)

  header_auth = 'OAuth ' + ', '.join(['%s="%s"' % (key, key_dict[key]) for key in HEADER_AUTH_KEYS])

  data = urllib.urlencode(url_values)
  api_request = urllib2.Request(TWITTER_API_URL + "?" + data, headers = {'Authorization': header_auth})

  try:
    api_response = urllib2.urlopen(api_request).read()
  except:
    raise IOError("Unable to reach %s" % TWITTER_API_URL)

  return json.loads(api_response)

tor_process = stem.process.launch_tor_with_config(
  config = {
    'SocksPort': str(SOCKS_PORT),
    'ExitNodes': '{ru}',
  },
)

try:
  for index, tweet in enumerate(poll_twitter_feed('ioerror', 3)):
    print("%i. %s" % (index + 1, tweet["created_at"]))
    print(tweet["text"])
    print("")
except IOError as exc:
  print(exc)
finally:
  tor_process.kill()  # stops tor
