"""
Unit tests for the stem.response.events classes.
"""

import datetime
import threading
import unittest

import stem.response
import stem.response.events
import test.mocking as mocking

from stem import * # enums and exceptions

# CIRC events from tor v0.2.3.16

CIRC_LAUNCHED = "650 CIRC 7 LAUNCHED \
BUILD_FLAGS=NEED_CAPACITY \
PURPOSE=GENERAL \
TIME_CREATED=2012-11-08T16:48:38.417238"

CIRC_EXTENDED = "650 CIRC 7 EXTENDED \
$999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz \
BUILD_FLAGS=NEED_CAPACITY \
PURPOSE=GENERAL \
TIME_CREATED=2012-11-08T16:48:38.417238"

CIRC_FAILED = "650 CIRC 5 FAILED \
$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9=ergebnisoffen \
BUILD_FLAGS=NEED_CAPACITY \
PURPOSE=GENERAL \
TIME_CREATED=2012-11-08T16:48:36.400959 \
REASON=DESTROYED \
REMOTE_REASON=OR_CONN_CLOSED"

# CIRC events from tor v0.2.1.30 without the VERBOSE_NAMES feature

CIRC_LAUNCHED_OLD = "650 CIRC 4 LAUNCHED"
CIRC_EXTENDED_OLD = "650 CIRC 1 EXTENDED \
$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone"
CIRC_BUILT_OLD = "650 CIRC 1 BUILT \
$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone,PrivacyRepublic14"

# STREAM events from tor 0.2.3.16 for visiting the google front page

STREAM_NEW = "650 STREAM 18 NEW 0 \
encrypted.google.com:443 \
SOURCE_ADDR=127.0.0.1:47849 \
PURPOSE=USER"

STREAM_SENTCONNECT = "650 STREAM 18 SENTCONNECT 26 encrypted.google.com:443"
STREAM_REMAP = "650 STREAM 18 REMAP 26 74.125.227.129:443 SOURCE=EXIT"
STREAM_SUCCEEDED = "650 STREAM 18 SUCCEEDED 26 74.125.227.129:443"
STREAM_CLOSED_RESET = "650 STREAM 21 CLOSED 26 74.125.227.129:443 REASON=CONNRESET"
STREAM_CLOSED_DONE = "650 STREAM 25 CLOSED 26 199.7.52.72:80 REASON=DONE"

# ORCONN events from starting tor 0.2.2.39 via TBB

ORCONN_CONNECTED = "650 ORCONN $7ED90E2833EE38A75795BA9237B0A4560E51E1A0=GreenDragon CONNECTED"
ORCONN_CLOSED = "650 ORCONN $A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1~tama CLOSED REASON=DONE"

# NEWDESC events. I've never actually seen multiple descriptors in an event,
# but the spec allows for it.

NEWDESC_SINGLE = "650 NEWDESC $B3FA3110CC6F42443F039220C134CBD2FC4F0493=Sakura"
NEWDESC_MULTIPLE = "650 NEWDESC $BE938957B2CA5F804B3AFC2C1EE6673170CDBBF8=Moonshine \
$B4BE08B22D4D2923EDC3970FD1B93D0448C6D8FF~Unnamed"

# ADDRMAP event
# TODO: it would be nice to have an example of an error event

ADDRMAP = '650 ADDRMAP www.atagar.com 75.119.206.243 "2012-11-19 00:50:13" \
EXPIRES="2012-11-19 08:50:13"'

def _get_event(content):
  controller_event = mocking.get_message(content)
  stem.response.convert("EVENT", controller_event, arrived_at = 25)
  return controller_event

class TestEvents(unittest.TestCase):
  def test_example(self):
    """
    Exercises the add_event_listener() pydoc example, but without the sleep().
    """
    
    import time
    from stem.control import Controller, EventType
    
    def print_bw(event):
      msg = "sent: %i, received: %i" % (event.written, event.read)
      self.assertEqual("sent: 25, received: 15", msg)
    
    def event_sender():
      for i in xrange(3):
        print_bw(_get_event("650 BW 15 25"))
        time.sleep(0.05)
    
    controller = mocking.get_object(Controller, {
      'authenticate': mocking.no_op(),
      'add_event_listener': mocking.no_op(),
    })
    
    controller.authenticate()
    controller.add_event_listener(print_bw, EventType.BW)
    
    events_thread = threading.Thread(target = event_sender)
    events_thread.start()
    time.sleep(0.2)
    events_thread.join()
  
  def test_log_events(self):
    event = _get_event("650 DEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.")
    
    self.assertTrue(isinstance(event, stem.response.events.LogEvent))
    self.assertEqual("DEBUG", event.runlevel)
    self.assertEqual("connection_edge_process_relay_cell(): Got an extended cell! Yay.", event.message)
    
    event = _get_event("650 INFO circuit_finish_handshake(): Finished building circuit hop:")
    
    self.assertTrue(isinstance(event, stem.response.events.LogEvent))
    self.assertEqual("INFO", event.runlevel)
    self.assertEqual("circuit_finish_handshake(): Finished building circuit hop:", event.message)
    
    event = _get_event("650+WARN\na multi-line\nwarning message\n.\n650 OK\n")
    
    self.assertTrue(isinstance(event, stem.response.events.LogEvent))
    self.assertEqual("WARN", event.runlevel)
    self.assertEqual("a multi-line\nwarning message", event.message)
  
  def test_addrmap_event(self):
    event = _get_event(ADDRMAP)
    
    self.assertTrue(isinstance(event, stem.response.events.AddrMapEvent))
    self.assertEqual(ADDRMAP.lstrip("650 "), str(event))
    self.assertEqual("www.atagar.com", event.hostname)
    self.assertEqual("75.119.206.243", event.destination)
    self.assertEqual(datetime.datetime(2012, 11, 19, 0, 50, 13), event.expiry)
    self.assertEqual(None, event.error)
    self.assertEqual(datetime.datetime(2012, 11, 19, 8, 50, 13), event.gmt_expiry)
  
  def test_bw_event(self):
    event = _get_event("650 BW 15 25")
    
    self.assertTrue(isinstance(event, stem.response.events.BandwidthEvent))
    self.assertEqual(15, event.read)
    self.assertEqual(25, event.written)
    
    event = _get_event("650 BW 0 0")
    self.assertEqual(0, event.read)
    self.assertEqual(0, event.written)
    
    # BW events are documented as possibly having various keywords including
    # DIR, OR, EXIT, and APP in the future. This is kinda a pointless note
    # since tor doesn't actually do it yet (and likely never will), but might
    # as well sanity test that it'll be ok.
    
    event = _get_event("650 BW 10 20 OR=5 EXIT=500")
    self.assertEqual(10, event.read)
    self.assertEqual(20, event.written)
    self.assertEqual({'OR': '5', 'EXIT': '500'}, event.keyword_args)
    
    self.assertRaises(ProtocolError, _get_event, "650 BW 15")
    self.assertRaises(ProtocolError, _get_event, "650 BW -15 25")
    self.assertRaises(ProtocolError, _get_event, "650 BW 15 -25")
    self.assertRaises(ProtocolError, _get_event, "650 BW x 25")
  
  def test_circ_event(self):
    event = _get_event(CIRC_LAUNCHED)
    
    self.assertTrue(isinstance(event, stem.response.events.CircuitEvent))
    self.assertEqual(CIRC_LAUNCHED.lstrip("650 "), str(event))
    self.assertEqual("7", event.id)
    self.assertEqual(CircStatus.LAUNCHED, event.status)
    self.assertEqual((), event.path)
    self.assertEqual((CircBuildFlag.NEED_CAPACITY,), event.build_flags)
    self.assertEqual(CircPurpose.GENERAL, event.purpose)
    self.assertEqual(None, event.hs_state)
    self.assertEqual(None, event.rend_query)
    self.assertEqual(datetime.datetime(2012, 11, 8, 16, 48, 38, 417238), event.created)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    
    event = _get_event(CIRC_EXTENDED)
    
    self.assertTrue(isinstance(event, stem.response.events.CircuitEvent))
    self.assertEqual(CIRC_EXTENDED.lstrip("650 "), str(event))
    self.assertEqual("7", event.id)
    self.assertEqual(CircStatus.EXTENDED, event.status)
    self.assertEqual((("999A226EBED397F331B612FE1E4CFAE5C1F201BA", "piyaz"),), event.path)
    self.assertEqual((CircBuildFlag.NEED_CAPACITY,), event.build_flags)
    self.assertEqual(CircPurpose.GENERAL, event.purpose)
    self.assertEqual(None, event.hs_state)
    self.assertEqual(None, event.rend_query)
    self.assertEqual(datetime.datetime(2012, 11, 8, 16, 48, 38, 417238), event.created)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    
    event = _get_event(CIRC_FAILED)
    
    self.assertTrue(isinstance(event, stem.response.events.CircuitEvent))
    self.assertEqual(CIRC_FAILED.lstrip("650 "), str(event))
    self.assertEqual("5", event.id)
    self.assertEqual(CircStatus.FAILED, event.status)
    self.assertEqual((("E57A476CD4DFBD99B4EE52A100A58610AD6E80B9", "ergebnisoffen"),), event.path)
    self.assertEqual((CircBuildFlag.NEED_CAPACITY,), event.build_flags)
    self.assertEqual(CircPurpose.GENERAL, event.purpose)
    self.assertEqual(None, event.hs_state)
    self.assertEqual(None, event.rend_query)
    self.assertEqual(datetime.datetime(2012, 11, 8, 16, 48, 36, 400959), event.created)
    self.assertEqual(CircClosureReason.DESTROYED, event.reason)
    self.assertEqual(CircClosureReason.OR_CONN_CLOSED, event.remote_reason)
    
    event = _get_event(CIRC_LAUNCHED_OLD)
    
    self.assertTrue(isinstance(event, stem.response.events.CircuitEvent))
    self.assertEqual(CIRC_LAUNCHED_OLD.lstrip("650 "), str(event))
    self.assertEqual("4", event.id)
    self.assertEqual(CircStatus.LAUNCHED, event.status)
    self.assertEqual((), event.path)
    self.assertEqual(None, event.build_flags)
    self.assertEqual(None, event.purpose)
    self.assertEqual(None, event.hs_state)
    self.assertEqual(None, event.rend_query)
    self.assertEqual(None, event.created)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    
    event = _get_event(CIRC_EXTENDED_OLD)
    
    self.assertTrue(isinstance(event, stem.response.events.CircuitEvent))
    self.assertEqual(CIRC_EXTENDED_OLD.lstrip("650 "), str(event))
    self.assertEqual("1", event.id)
    self.assertEqual(CircStatus.EXTENDED, event.status)
    self.assertEqual((("E57A476CD4DFBD99B4EE52A100A58610AD6E80B9", None), (None,"hamburgerphone")), event.path)
    self.assertEqual(None, event.build_flags)
    self.assertEqual(None, event.purpose)
    self.assertEqual(None, event.hs_state)
    self.assertEqual(None, event.rend_query)
    self.assertEqual(None, event.created)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    
    event = _get_event(CIRC_BUILT_OLD)
    
    self.assertTrue(isinstance(event, stem.response.events.CircuitEvent))
    self.assertEqual(CIRC_BUILT_OLD.lstrip("650 "), str(event))
    self.assertEqual("1", event.id)
    self.assertEqual(CircStatus.BUILT, event.status)
    self.assertEqual((("E57A476CD4DFBD99B4EE52A100A58610AD6E80B9", None), (None,"hamburgerphone"), (None, "PrivacyRepublic14")), event.path)
    self.assertEqual(None, event.build_flags)
    self.assertEqual(None, event.purpose)
    self.assertEqual(None, event.hs_state)
    self.assertEqual(None, event.rend_query)
    self.assertEqual(None, event.created)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
  
  def test_newdesc_event(self):
    event = _get_event(NEWDESC_SINGLE)
    expected_relays = (("B3FA3110CC6F42443F039220C134CBD2FC4F0493", "Sakura"),)
    
    self.assertTrue(isinstance(event, stem.response.events.NewDescEvent))
    self.assertEqual(NEWDESC_SINGLE.lstrip("650 "), str(event))
    self.assertEqual(expected_relays, event.relays)
    
    event = _get_event(NEWDESC_MULTIPLE)
    expected_relays = (("BE938957B2CA5F804B3AFC2C1EE6673170CDBBF8", "Moonshine"),
                       ("B4BE08B22D4D2923EDC3970FD1B93D0448C6D8FF", "Unnamed"))
    
    self.assertTrue(isinstance(event, stem.response.events.NewDescEvent))
    self.assertEqual(NEWDESC_MULTIPLE.lstrip("650 "), str(event))
    self.assertEqual(expected_relays, event.relays)
  
  def test_orconn_event(self):
    event = _get_event(ORCONN_CONNECTED)
    
    self.assertTrue(isinstance(event, stem.response.events.ORConnEvent))
    self.assertEqual(ORCONN_CONNECTED.lstrip("650 "), str(event))
    self.assertEqual("$7ED90E2833EE38A75795BA9237B0A4560E51E1A0=GreenDragon", event.endpoint)
    self.assertEqual("7ED90E2833EE38A75795BA9237B0A4560E51E1A0", event.endpoint_fingerprint)
    self.assertEqual("GreenDragon", event.endpoint_nickname)
    self.assertEqual(None, event.endpoint_address)
    self.assertEqual(None, event.endpoint_port)
    self.assertEqual(ORStatus.CONNECTED, event.status)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.circ_count)
    
    event = _get_event(ORCONN_CLOSED)
    
    self.assertTrue(isinstance(event, stem.response.events.ORConnEvent))
    self.assertEqual(ORCONN_CLOSED.lstrip("650 "), str(event))
    self.assertEqual("$A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1~tama", event.endpoint)
    self.assertEqual("A1130635A0CDA6F60C276FBF6994EFBD4ECADAB1", event.endpoint_fingerprint)
    self.assertEqual("tama", event.endpoint_nickname)
    self.assertEqual(None, event.endpoint_address)
    self.assertEqual(None, event.endpoint_port)
    self.assertEqual(ORStatus.CLOSED, event.status)
    self.assertEqual(ORClosureReason.DONE, event.reason)
    self.assertEqual(None, event.circ_count)
  
  def test_stream_event(self):
    event = _get_event(STREAM_NEW)
    
    self.assertTrue(isinstance(event, stem.response.events.StreamEvent))
    self.assertEqual(STREAM_NEW.lstrip("650 "), str(event))
    self.assertEqual("18", event.id)
    self.assertEqual(StreamStatus.NEW, event.status)
    self.assertEqual(None, event.circ_id)
    self.assertEqual("encrypted.google.com:443", event.target)
    self.assertEqual("encrypted.google.com", event.target_address)
    self.assertEqual(443, event.target_port)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    self.assertEqual(None, event.source)
    self.assertEqual("127.0.0.1:47849", event.source_addr)
    self.assertEqual("127.0.0.1", event.source_address)
    self.assertEqual(47849, event.source_port)
    self.assertEqual(StreamPurpose.USER, event.purpose)
    
    event = _get_event(STREAM_SENTCONNECT)
    
    self.assertTrue(isinstance(event, stem.response.events.StreamEvent))
    self.assertEqual(STREAM_SENTCONNECT.lstrip("650 "), str(event))
    self.assertEqual("18", event.id)
    self.assertEqual(StreamStatus.SENTCONNECT, event.status)
    self.assertEqual("26", event.circ_id)
    self.assertEqual("encrypted.google.com:443", event.target)
    self.assertEqual("encrypted.google.com", event.target_address)
    self.assertEqual(443, event.target_port)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    self.assertEqual(None, event.source)
    self.assertEqual(None, event.source_addr)
    self.assertEqual(None, event.source_address)
    self.assertEqual(None, event.source_port)
    self.assertEqual(None, event.purpose)
    
    event = _get_event(STREAM_REMAP)
    
    self.assertTrue(isinstance(event, stem.response.events.StreamEvent))
    self.assertEqual(STREAM_REMAP.lstrip("650 "), str(event))
    self.assertEqual("18", event.id)
    self.assertEqual(StreamStatus.REMAP, event.status)
    self.assertEqual("26", event.circ_id)
    self.assertEqual("74.125.227.129:443", event.target)
    self.assertEqual("74.125.227.129", event.target_address)
    self.assertEqual(443, event.target_port)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    self.assertEqual(StreamSource.EXIT, event.source)
    self.assertEqual(None, event.source_addr)
    self.assertEqual(None, event.source_address)
    self.assertEqual(None, event.source_port)
    self.assertEqual(None, event.purpose)
    
    event = _get_event(STREAM_SUCCEEDED)
    
    self.assertTrue(isinstance(event, stem.response.events.StreamEvent))
    self.assertEqual(STREAM_SUCCEEDED.lstrip("650 "), str(event))
    self.assertEqual("18", event.id)
    self.assertEqual(StreamStatus.SUCCEEDED, event.status)
    self.assertEqual("26", event.circ_id)
    self.assertEqual("74.125.227.129:443", event.target)
    self.assertEqual("74.125.227.129", event.target_address)
    self.assertEqual(443, event.target_port)
    self.assertEqual(None, event.reason)
    self.assertEqual(None, event.remote_reason)
    self.assertEqual(None, event.source)
    self.assertEqual(None, event.source_addr)
    self.assertEqual(None, event.source_address)
    self.assertEqual(None, event.source_port)
    self.assertEqual(None, event.purpose)
    
    event = _get_event(STREAM_CLOSED_RESET)
    
    self.assertTrue(isinstance(event, stem.response.events.StreamEvent))
    self.assertEqual(STREAM_CLOSED_RESET.lstrip("650 "), str(event))
    self.assertEqual("21", event.id)
    self.assertEqual(StreamStatus.CLOSED, event.status)
    self.assertEqual("26", event.circ_id)
    self.assertEqual("74.125.227.129:443", event.target)
    self.assertEqual("74.125.227.129", event.target_address)
    self.assertEqual(443, event.target_port)
    self.assertEqual(StreamClosureReason.CONNRESET, event.reason)
    self.assertEqual(None, event.remote_reason)
    self.assertEqual(None, event.source)
    self.assertEqual(None, event.source_addr)
    self.assertEqual(None, event.source_address)
    self.assertEqual(None, event.source_port)
    self.assertEqual(None, event.purpose)
    
    event = _get_event(STREAM_CLOSED_DONE)
    
    self.assertTrue(isinstance(event, stem.response.events.StreamEvent))
    self.assertEqual(STREAM_CLOSED_DONE.lstrip("650 "), str(event))
    self.assertEqual("25", event.id)
    self.assertEqual(StreamStatus.CLOSED, event.status)
    self.assertEqual("26", event.circ_id)
    self.assertEqual("199.7.52.72:80", event.target)
    self.assertEqual("199.7.52.72", event.target_address)
    self.assertEqual(80, event.target_port)
    self.assertEqual(StreamClosureReason.DONE, event.reason)
    self.assertEqual(None, event.remote_reason)
    self.assertEqual(None, event.source)
    self.assertEqual(None, event.source_addr)
    self.assertEqual(None, event.source_address)
    self.assertEqual(None, event.source_port)
    self.assertEqual(None, event.purpose)

