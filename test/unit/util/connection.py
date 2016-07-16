"""
Unit tests for the stem.util.connection functions.
"""

import platform
import unittest

import stem.util.connection

from stem.util.connection import Resolver, Connection

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

NETSTAT_OUTPUT = """\
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.0.1:5939        73.94.23.87:443         ESTABLISHED 20586/firefox
tcp        0      0 192.168.0.1:4325        73.94.23.55:443         ESTABLISHED 20586/firefox
tcp        1      0 192.168.0.1:4378        29.208.141.42:443       CLOSE_WAIT  20586/firefox
tcp        0      0 127.0.0.1:22            127.0.0.1:56673         ESTABLISHED -
tcp        0    586 192.168.0.1:44284       38.229.79.2:443         ESTABLISHED 15843/tor
tcp        0      0 192.168.0.1:37909       16.111.19.278:6697      ESTABLISHED -
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name    Path
unix  14     [ ]         DGRAM                    8433     -                   /dev/log
unix  3      [ ]         STREAM     CONNECTED     34164277 15843/tor
unix  3      [ ]         STREAM     CONNECTED     34164276 15843/tor
unix  3      [ ]         STREAM     CONNECTED     7951     -
"""

NETSTAT_IPV6_OUTPUT = """\
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp6       0      0 5.9.158.75:5222         80.171.220.248:48910    ESTABLISHED 9820/beam
tcp6       0      0 2a01:4f8:190:514a::2:443 2001:638:a000:4140::ffff:189:41046 ESTABLISHED 1904/tor
tcp6       0      0 5.9.158.75:5269         146.255.57.226:38703    ESTABLISHED 9820/beam
tcp6       0      0 2a01:4f8:190:514a::2:443 2001:858:2:2:aabb:0:563b:1526:38260 ESTABLISHED 1904/tor
tcp6       0      0 5.9.158.75:5222         80.171.220.248:48966    ESTABLISHED 9820/beam
"""

NETSTAT_WINDOWS_OUTPUT = """\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       852
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:902            0.0.0.0:0              LISTENING       2076
  TCP    0.0.0.0:912            0.0.0.0:0              LISTENING       2076
  TCP    192.168.0.1:44284      38.229.79.2:443        ESTABLISHED     15843
  TCP    0.0.0.0:37782          0.0.0.0:0              LISTENING       4128
"""

SS_OUTPUT = """\
Netid  State      Recv-Q Send-Q     Local Address:Port       Peer Address:Port
tcp    CLOSE-WAIT 1      0           192.168.0.1:43780      53.203.145.45:443    users:(("firefox",20586,118))
tcp    ESTAB      55274  0           192.168.0.1:46136     196.153.236.35:80     users:(("firefox",20586,93))
tcp    ESTAB      0      0           192.168.0.1:44092      23.112.135.72:443    users:(("tor",15843,10))
tcp    ESTAB      0      0              127.0.0.1:22            127.0.0.1:56673
tcp    ESTAB      0      0           192.168.0.1:44415        38.229.79.2:443    users:(("tor",15843,9))
"""

SS_IPV6_OUTPUT = """\
Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port
tcp    ESTAB      0      0      5.9.158.75:443                107.170.93.13:56159               users:(("tor",pid=25056,fd=997))
tcp    ESTAB      0      0      5.9.158.75:443                159.203.97.91:37802               users:(("tor",pid=25056,fd=77))
tcp    ESTAB      0      0      2a01:4f8:190:514a::2:443                2001:638:a000:4140::ffff:189:38556               users:(("tor",pid=25056,fd=3175))
tcp    ESTAB      0      0         ::ffff:5.9.158.75:5222                ::ffff:78.54.131.65:34950               users:(("beam",pid=1712,fd=29))
tcp    ESTAB      0      0      2a01:4f8:190:514a::2:443                   2001:858:2:2:aabb:0:563b:1526:51428               users:(("tor",pid=25056,fd=3248))
tcp    ESTAB      0      0         ::ffff:5.9.158.75:5222                ::ffff:78.54.131.65:34882               users:(("beam",pid=1712,fd=26))
"""

LSOF_OUTPUT = """\
COMMAND     PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
ubuntu-ge  2164 atagar   11u  IPv4    13593      0t0  TCP 192.168.0.1:55395->21.89.91.78:80 (CLOSE_WAIT)
tor       15843 atagar    6u  IPv4 34164278      0t0  TCP 127.0.0.1:9050 (LISTEN)
tor       15843 atagar    7u  IPv4 34164279      0t0  TCP 127.0.0.1:9051 (LISTEN)
tor       15843 atagar    9u  IPv4 34188132      0t0  TCP 192.168.0.1:44415->38.229.79.2:443 (ESTABLISHED)
tor       15843 atagar   10u  IPv4 34165291      0t0  TCP 192.168.0.1:44092->68.169.35.102:443 (ESTABLISHED)
python    16422 atagar    3u  IPv4 34203773      0t0  UDP 127.0.0.1:39624->127.0.0.1:53
firefox   20586 atagar   66u  IPv4  5765353      0t0  TCP 192.168.0.1:47486->62.135.16.134:443 (ESTABLISHED)
firefox   20586 atagar   71u  IPv4 13094989      0t0  TCP 192.168.0.1:43762->182.3.10.42:443 (CLOSE_WAIT)
"""

LSOF_IPV6_OUTPUT = """\
COMMAND  PID     USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
ntpd    1818     root   20u  IPv6      530      0t0  UDP [::1]:123
ntpd    1818     root   21u  IPv6      532      0t0  UDP [2a01:4f8:190:514a::2]:123
ntpd    1818     root   22u  IPv6      534      0t0  UDP [fe80::3285:a9ff:feed:1cb]:123
tor     1904      tor   10u  IPv6     4372      0t0  TCP [2a01:4f8:190:514a::2]:443 (LISTEN)
tor     1904      tor 3228u  IPv6 10303350      0t0  TCP [2a01:4f8:190:514a::2]:443->[2001:858:2:2:aabb:0:563b:1526]:44811 (ESTABLISHED)
"""

LSOF_OUTPUT_OSX = """\
tor       129 atagar    4u  IPv4 0xffffff3527af0500      0t0  TCP 127.0.0.1:9051 (LISTEN)
tor       129 atagar    5u  IPv4 0xffffff363af9de40      0t0  TCP 192.168.1.10:9090 (LISTEN)
tor       129 atagar    6u  IPv4 0xffffff306a960a40      0t0  TCP 192.168.1.10:9091 (LISTEN)
tor       129 atagar    8u  IPv6 0xffffff13f5575a98      0t0  UDP *:48718
tor       129 atagar    9u  IPv6 0xffffff1b2273a178      0t0  UDP *:48714
tor       129 atagar   10u  IPv6 0xffffff1b473a9758      0t0  UDP *:48716
tor       129 atagar   11u  IPv6 0xffffff1b5733aa48      0t0  UDP *:48719
tor       129 atagar   12u  IPv4 0xffffff1cc6dd0160      0t0  TCP 192.168.1.20:9090->38.229.79.2:14010 (ESTABLISHED)
tor       129 atagar   22u  IPv4 0xffffff35c9125500      0t0  TCP 192.168.1.20:9090->68.169.35.102:14815 (ESTABLISHED)
tor       129 atagar   23u  IPv4 0xffffff3236168160      0t0  TCP 192.168.1.20:9090->62.135.16.134:14456 (ESTABLISHED)
"""

SOCKSTAT_OUTPUT = """\
USER     PROCESS              PID      PROTO  SOURCE ADDRESS            FOREIGN ADDRESS           STATE
atagar   ubuntu-geoip-pr      2164     tcp4   192.168.0.1:55395         141.18.34.33:80           CLOSE_WAIT
atagar   tor                  15843    tcp4   127.0.0.1:9050            *:*                       LISTEN
atagar   tor                  15843    tcp4   127.0.0.1:9051            *:*                       LISTEN
atagar   tor                  15843    tcp4   192.168.0.1:44415         38.229.79.2:443           ESTABLISHED
atagar   tor                  15843    tcp4   192.168.0.1:44092         68.169.35.102:443         ESTABLISHED
atagar   firefox              20586    tcp4   192.168.0.1:47486         213.24.100.160:443        ESTABLISHED
atagar   firefox              20586    tcp4   192.168.0.1:43762         32.188.221.72:443         CLOSE_WAIT
"""

# I don't have actual sockstat and procstat output for FreeBSD. Rather, these
# are snippets of output from email threads.

BSD_SOCKSTAT_OUTPUT = """\
_tor     tor        4397  7  tcp4   172.27.72.202:9050    *:*
_tor     tor        4397  8  udp4   172.27.72.202:53      *:*
_tor     tor        4397  9  tcp4   172.27.72.202:9051    *:*
_tor     tor        4397  12 tcp4   172.27.72.202:54011   38.229.79.2:9001
_tor     tor        4397  15 tcp4   172.27.72.202:59374   68.169.35.102:9001
_tor     tor        4397  19 tcp4   172.27.72.202:59673   213.24.100.160:9001
_tor     tor        4397  20 tcp4   172.27.72.202:51946   32.188.221.72:443
_tor     tor        4397  22 tcp4   172.27.72.202:60344   21.89.91.78:9001
"""

BSD_PROCSTAT_OUTPUT = """\
  PID COMM               FD T V FLAGS    REF  OFFSET PRO NAME
 3561 tor                 4 s - rw---n--   2       0 TCP 10.0.0.2:9050 10.0.0.1:22370
 3561 tor                 5 s - rw---n--   2       0 TCP 10.0.0.2:9050 0.0.0.0:0
 3561 tor                 6 s - rw---n--   2       0 TCP 10.0.0.2:9040 0.0.0.0:0
 3561 tor                 7 s - rw---n--   2       0 UDP 10.0.0.2:53 0.0.0.0:0
 3561 tor                 8 s - rw---n--   2       0 TCP 10.0.0.2:9051 0.0.0.0:0
 3561 tor                14 s - rw---n--   2       0 TCP 10.0.0.2:9050 10.0.0.1:44381
 3561 tor                15 s - rw---n--   2       0 TCP 10.0.0.2:33734 38.229.79.2:443
 3561 tor                16 s - rw---n--   2       0 TCP 10.0.0.2:47704 68.169.35.102:9001
"""


class TestConnection(unittest.TestCase):
  @patch('os.access')
  @patch('stem.util.system.is_available')
  @patch('stem.util.proc.is_available')
  def test_system_resolvers(self, proc_mock, is_available_mock, os_mock):
    """
    Checks the system_resolvers function.
    """

    is_available_mock.return_value = True
    proc_mock.return_value = False
    os_mock.return_value = True

    self.assertEqual([Resolver.NETSTAT_WINDOWS], stem.util.connection.system_resolvers('Windows'))
    self.assertEqual([Resolver.LSOF], stem.util.connection.system_resolvers('Darwin'))
    self.assertEqual([Resolver.LSOF], stem.util.connection.system_resolvers('OpenBSD'))
    self.assertEqual([Resolver.BSD_SOCKSTAT, Resolver.BSD_PROCSTAT, Resolver.LSOF], stem.util.connection.system_resolvers('FreeBSD'))
    self.assertEqual([Resolver.NETSTAT, Resolver.SOCKSTAT, Resolver.LSOF, Resolver.SS], stem.util.connection.system_resolvers('Linux'))

    proc_mock.return_value = True
    self.assertEqual([Resolver.PROC, Resolver.NETSTAT, Resolver.SOCKSTAT, Resolver.LSOF, Resolver.SS], stem.util.connection.system_resolvers('Linux'))

    # check that calling without an argument is equivalent to calling for this
    # platform

    self.assertEqual(stem.util.connection.system_resolvers(platform.system()), stem.util.connection.system_resolvers())

    # check that lacking commands in our PATH drops them from the results

    is_available_mock.return_value = False
    self.assertEqual([Resolver.PROC], stem.util.connection.system_resolvers('Linux'))

  def test_port_usage(self):
    """
    Check that port_usage can load our config and provide the expected results.
    """

    self.assertEqual('HTTP', stem.util.connection.port_usage(80))
    self.assertEqual('HTTP', stem.util.connection.port_usage('80'))  # query with a string
    self.assertEqual('BitTorrent', stem.util.connection.port_usage(6881))  # min and max value of a range
    self.assertEqual('BitTorrent', stem.util.connection.port_usage(6999))
    self.assertEqual(None, stem.util.connection.port_usage(30000))  # unrecognized port

  @patch('stem.util.proc.connections')
  def test_get_connections_by_proc(self, proc_mock):
    """
    Checks the get_connections function with the proc resolver.
    """

    proc_mock.return_value = [
      ('17.17.17.17', 4369, '34.34.34.34', 8738, 'tcp', False),
      ('187.187.187.187', 48059, '204.204.204.204', 52428, 'tcp', False),
    ]

    expected = [
      Connection('17.17.17.17', 4369, '34.34.34.34', 8738, 'tcp', False),
      Connection('187.187.187.187', 48059, '204.204.204.204', 52428, 'tcp', False),
    ]

    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.PROC, process_pid = 1111))

    proc_mock.side_effect = IOError('No connections for you!')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.PROC, process_pid = 1111)

  @patch('stem.util.system.call')
  def test_get_connections_by_netstat(self, call_mock):
    """
    Checks the get_connections function with the netstat resolver.
    """

    call_mock.return_value = NETSTAT_OUTPUT.split('\n')
    expected = [Connection('192.168.0.1', 44284, '38.229.79.2', 443, 'tcp', False)]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.NETSTAT, process_pid = 15843, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.NETSTAT, process_pid = 15843, process_name = 'stuff')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.NETSTAT, process_pid = 1111, process_name = 'tor')

    call_mock.side_effect = OSError('Unable to call netstat')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.NETSTAT, process_pid = 1111)

  @patch('stem.util.system.call', Mock(return_value = NETSTAT_IPV6_OUTPUT.split('\n')))
  def test_get_connections_by_netstat_ipv6(self):
    """
    Checks the get_connections function with the netstat resolver for IPv6.
    """

    expected = [
      Connection('2a01:4f8:190:514a::2', 443, '2001:638:a000:4140::ffff:189', 41046, 'tcp', True),
      Connection('2a01:4f8:190:514a::2', 443, '2001:858:2:2:aabb:0:563b:1526', 38260, 'tcp', True),
    ]

    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.NETSTAT, process_pid = 1904, process_name = 'tor'))

  @patch('stem.util.system.call')
  def test_get_connections_by_windows_netstat(self, call_mock):
    """
    Checks the get_connections function with the Windows netstat resolver.
    """

    call_mock.return_value = NETSTAT_WINDOWS_OUTPUT.split('\n')
    expected = [Connection('192.168.0.1', 44284, '38.229.79.2', 443, 'tcp', False)]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.NETSTAT_WINDOWS, process_pid = 15843, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.NETSTAT_WINDOWS, process_pid = 1111, process_name = 'tor')
    call_mock.side_effect = OSError('Unable to call netstat')

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.NETSTAT_WINDOWS, process_pid = 1111)

  @patch('stem.util.system.call')
  def test_get_connections_by_ss(self, call_mock):
    """
    Checks the get_connections function with the ss resolver.
    """

    call_mock.return_value = SS_OUTPUT.split('\n')
    expected = [
      Connection('192.168.0.1', 44092, '23.112.135.72', 443, 'tcp', False),
      Connection('192.168.0.1', 44415, '38.229.79.2', 443, 'tcp', False),
    ]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.SS, process_pid = 15843, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.SS, process_pid = 15843, process_name = 'stuff')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.SS, process_pid = 1111, process_name = 'tor')

    call_mock.side_effect = OSError('Unable to call ss')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.SS, process_pid = 1111)

  @patch('stem.util.system.call', Mock(return_value = SS_IPV6_OUTPUT.split('\n')))
  def test_get_connections_by_ss_ipv6(self):
    """
    Checks the get_connections function with the ss resolver results on IPv6
    conections. This also checks with the output from a hardened Gentoo system
    which has subtle differences...

      https://trac.torproject.org/projects/tor/ticket/18079
    """

    expected = [
      Connection('5.9.158.75', 443, '107.170.93.13', 56159, 'tcp', False),
      Connection('5.9.158.75', 443, '159.203.97.91', 37802, 'tcp', False),
      Connection('2a01:4f8:190:514a::2', 443, '2001:638:a000:4140::ffff:189', 38556, 'tcp', True),
      Connection('2a01:4f8:190:514a::2', 443, '2001:858:2:2:aabb:0:563b:1526', 51428, 'tcp', True),
    ]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.SS, process_pid = 25056, process_name = 'tor'))
    self.assertEqual(2, len(stem.util.connection.get_connections(Resolver.SS, process_name = 'beam')))

  @patch('stem.util.system.call')
  def test_get_connections_by_lsof(self, call_mock):
    """
    Checks the get_connections function with the lsof resolver.
    """

    call_mock.return_value = LSOF_OUTPUT.split('\n')
    expected = [
      Connection('192.168.0.1', 44415, '38.229.79.2', 443, 'tcp', False),
      Connection('192.168.0.1', 44092, '68.169.35.102', 443, 'tcp', False),
    ]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.LSOF, process_pid = 15843, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.LSOF, process_pid = 15843, process_name = 'stuff')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.LSOF, process_pid = 1111, process_name = 'tor')

    call_mock.side_effect = OSError('Unable to call lsof')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.LSOF, process_pid = 1111)

  @patch('stem.util.system.call', Mock(return_value = LSOF_IPV6_OUTPUT.split('\n')))
  def test_get_connections_by_lsof_ipv6(self):
    """
    Checks the get_connections function with the lsof resolver for IPv6.
    """

    expected = [Connection('2a01:4f8:190:514a::2', 443, '2001:858:2:2:aabb:0:563b:1526', 44811, 'tcp', True)]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.LSOF, process_pid = 1904, process_name = 'tor'))

  @patch('stem.util.system.call', Mock(return_value = LSOF_OUTPUT_OSX.split('\n')))
  def test_get_connections_by_lsof_osx(self):
    """
    Checks the get_connections function with the lsof resolver on OSX. This
    only includes entries for the tor process.
    """

    expected = [
      Connection('192.168.1.20', 9090, '38.229.79.2', 14010, 'tcp', False),
      Connection('192.168.1.20', 9090, '68.169.35.102', 14815, 'tcp', False),
      Connection('192.168.1.20', 9090, '62.135.16.134', 14456, 'tcp', False),
    ]

    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.LSOF, process_pid = 129, process_name = 'tor'))

  @patch('stem.util.system.call')
  def test_get_connections_by_sockstat(self, call_mock):
    """
    Checks the get_connections function with the sockstat resolver.
    """

    call_mock.return_value = SOCKSTAT_OUTPUT.split('\n')
    expected = [
      Connection('192.168.0.1', 44415, '38.229.79.2', 443, 'tcp', False),
      Connection('192.168.0.1', 44092, '68.169.35.102', 443, 'tcp', False),
    ]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.SOCKSTAT, process_pid = 15843, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.SOCKSTAT, process_pid = 15843, process_name = 'stuff')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.SOCKSTAT, process_pid = 1111, process_name = 'tor')

    call_mock.side_effect = OSError('Unable to call sockstat')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.SOCKSTAT, process_pid = 1111)

  @patch('stem.util.system.call')
  def test_get_connections_by_sockstat_for_bsd(self, call_mock):
    """
    Checks the get_connections function with the bsd variant of the sockstat
    resolver.
    """

    call_mock.return_value = BSD_SOCKSTAT_OUTPUT.split('\n')
    expected = [
      Connection('172.27.72.202', 54011, '38.229.79.2', 9001, 'tcp', False),
      Connection('172.27.72.202', 59374, '68.169.35.102', 9001, 'tcp', False),
      Connection('172.27.72.202', 59673, '213.24.100.160', 9001, 'tcp', False),
      Connection('172.27.72.202', 51946, '32.188.221.72', 443, 'tcp', False),
      Connection('172.27.72.202', 60344, '21.89.91.78', 9001, 'tcp', False),
    ]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.BSD_SOCKSTAT, process_pid = 4397, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.BSD_SOCKSTAT, process_pid = 4397, process_name = 'stuff')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.BSD_SOCKSTAT, process_pid = 1111, process_name = 'tor')

    call_mock.side_effect = OSError('Unable to call sockstat')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.BSD_SOCKSTAT, process_pid = 1111)

  @patch('stem.util.system.call')
  def test_get_connections_by_procstat(self, call_mock):
    """
    Checks the get_connections function with the procstat resolver.
    """

    call_mock.return_value = BSD_PROCSTAT_OUTPUT.split('\n')
    expected = [
      Connection('10.0.0.2', 9050, '10.0.0.1', 22370, 'tcp', False),
      Connection('10.0.0.2', 9050, '10.0.0.1', 44381, 'tcp', False),
      Connection('10.0.0.2', 33734, '38.229.79.2', 443, 'tcp', False),
      Connection('10.0.0.2', 47704, '68.169.35.102', 9001, 'tcp', False),
    ]
    self.assertEqual(expected, stem.util.connection.get_connections(Resolver.BSD_PROCSTAT, process_pid = 3561, process_name = 'tor'))

    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.BSD_PROCSTAT, process_pid = 3561, process_name = 'stuff')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.BSD_PROCSTAT, process_pid = 1111, process_name = 'tor')

    call_mock.side_effect = OSError('Unable to call procstat')
    self.assertRaises(IOError, stem.util.connection.get_connections, Resolver.BSD_PROCSTAT, process_pid = 1111)

  def test_is_valid_ipv4_address(self):
    """
    Checks the is_valid_ipv4_address function.
    """

    valid_addresses = (
      '0.0.0.0',
      '1.2.3.4',
      '192.168.0.1',
      '255.255.255.255',
    )

    invalid_addresses = (
      '0.0.00.0',
      '0.0.0',
      '1.2.3.256',
      '1.2.3.-1',
      '0.0.0.a',
      'a.b.c.d',
    )

    for address in valid_addresses:
      self.assertTrue(stem.util.connection.is_valid_ipv4_address(address))

    for address in invalid_addresses:
      self.assertFalse(stem.util.connection.is_valid_ipv4_address(address))

  def test_is_valid_ipv6_address(self):
    """
    Checks the is_valid_ipv6_address function.
    """

    valid_addresses = (
      'fe80:0000:0000:0000:0202:b3ff:fe1e:8329',
      'fe80:0:0:0:202:b3ff:fe1e:8329',
      'fe80::202:b3ff:fe1e:8329',
      '::ffff:5.9.158.75',
      '5.9.158.75::ffff',
      '::5.9.158.75:ffff',
      '::',
    )

    invalid_addresses = (
      'fe80:0000:0000:0000:0202:b3ff:fe1e:829g',
      'fe80:0000:0000:0000:0202:b3ff:fe1e: 8329',
      '2001:db8::aaaa::1',
      '::ffff:5.9.158.75.12',
      '::ffff:5.9.158',
      '::ffff:5.9',
      ':::',
      ':',
      '',
    )

    for address in valid_addresses:
      self.assertTrue(stem.util.connection.is_valid_ipv6_address(address), "%s isn't a valid IPv6 address" % address)

    for address in invalid_addresses:
      self.assertFalse(stem.util.connection.is_valid_ipv6_address(address), '%s should be an invalid IPv6 address' % address)

  def test_is_valid_port(self):
    """
    Checks the is_valid_port function.
    """

    valid_ports = (1, '1', 1234, '1234', 65535, '65535', [1, '2'])
    invalid_ports = (0, '0', 65536, '65536', 'abc', '*', ' 15', '01', True, {})

    for port in valid_ports:
      self.assertTrue(stem.util.connection.is_valid_port(port))

    for port in invalid_ports:
      self.assertFalse(stem.util.connection.is_valid_port(port))

    self.assertTrue(stem.util.connection.is_valid_port(0, allow_zero = True))
    self.assertTrue(stem.util.connection.is_valid_port('0', allow_zero = True))

  def test_is_private_address(self):
    """
    Checks the is_private_address function.
    """

    self.assertTrue(stem.util.connection.is_private_address('127.0.0.1'))
    self.assertTrue(stem.util.connection.is_private_address('10.0.0.0'))
    self.assertTrue(stem.util.connection.is_private_address('172.16.0.0'))
    self.assertTrue(stem.util.connection.is_private_address('172.31.0.0'))
    self.assertTrue(stem.util.connection.is_private_address('192.168.0.50'))

    self.assertFalse(stem.util.connection.is_private_address('74.125.28.103'))
    self.assertFalse(stem.util.connection.is_private_address('172.15.0.0'))
    self.assertFalse(stem.util.connection.is_private_address('172.32.0.0'))

    self.assertRaises(ValueError, stem.util.connection.is_private_address, '')
    self.assertRaises(ValueError, stem.util.connection.is_private_address, 'blarg')
    self.assertRaises(ValueError, stem.util.connection.is_private_address, '127.0.0')
    self.assertRaises(ValueError, stem.util.connection.is_private_address, 'fe80:0000:0000:0000:0202:b3ff:fe1e:8329')

  def test_address_to_int(self):
    """
    Checks the address_to_int function.
    """

    self.assertEqual(1, stem.util.connection.address_to_int('0.0.0.1'))
    self.assertEqual(2, stem.util.connection.address_to_int('0.0.0.2'))
    self.assertEqual(256, stem.util.connection.address_to_int('0.0.1.0'))
    self.assertEqual(2130706433, stem.util.connection.address_to_int('127.0.0.1'))
    self.assertEqual(338288524927261089654163772891438416681, stem.util.connection.address_to_int('fe80:0000:0000:0000:0202:b3ff:fe1e:8329'))

  def test_expand_ipv6_address(self):
    """
    Checks the expand_ipv6_address function.
    """

    test_values = {
      '2001:db8::ff00:42:8329': '2001:0db8:0000:0000:0000:ff00:0042:8329',
      '::': '0000:0000:0000:0000:0000:0000:0000:0000',
      '::1': '0000:0000:0000:0000:0000:0000:0000:0001',
      '1::1': '0001:0000:0000:0000:0000:0000:0000:0001',
      '::ffff:5.9.158.75': '0000:0000:0000:0000:0000:ffff:0509:9e4b',
      '5.9.158.75::ffff': '0509:9e4b:0000:0000:0000:0000:0000:ffff',
      '::5.9.158.75:ffff': '0000:0000:0000:0000:0000:0509:9e4b:ffff',
    }

    for test_arg, expected in test_values.items():
      self.assertEqual(expected, stem.util.connection.expand_ipv6_address(test_arg))

    self.assertRaises(ValueError, stem.util.connection.expand_ipv6_address, '127.0.0.1')

  def test_get_mask_ipv4(self):
    """
    Checks the get_mask_ipv4 function.
    """

    self.assertEqual('255.255.255.255', stem.util.connection.get_mask_ipv4(32))
    self.assertEqual('255.255.255.248', stem.util.connection.get_mask_ipv4(29))
    self.assertEqual('255.255.254.0', stem.util.connection.get_mask_ipv4(23))
    self.assertEqual('0.0.0.0', stem.util.connection.get_mask_ipv4(0))

    self.assertRaises(ValueError, stem.util.connection.get_mask_ipv4, -1)
    self.assertRaises(ValueError, stem.util.connection.get_mask_ipv4, 33)

  def test_get_mask_ipv6(self):
    """
    Checks the get_mask_ipv6 function.
    """

    self.assertEqual('FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', stem.util.connection.get_mask_ipv6(128))
    self.assertEqual('FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFE:0000', stem.util.connection.get_mask_ipv6(111))
    self.assertEqual('0000:0000:0000:0000:0000:0000:0000:0000', stem.util.connection.get_mask_ipv6(0))

    self.assertRaises(ValueError, stem.util.connection.get_mask_ipv6, -1)
    self.assertRaises(ValueError, stem.util.connection.get_mask_ipv6, 129)

  def test_get_masked_bits(self):
    """
    Checks the _get_masked_bits function.
    """

    self.assertEqual(32, stem.util.connection._get_masked_bits('255.255.255.255'))
    self.assertEqual(29, stem.util.connection._get_masked_bits('255.255.255.248'))
    self.assertEqual(23, stem.util.connection._get_masked_bits('255.255.254.0'))
    self.assertEqual(0, stem.util.connection._get_masked_bits('0.0.0.0'))

    self.assertRaises(ValueError, stem.util.connection._get_masked_bits, 'blarg')
    self.assertRaises(ValueError, stem.util.connection._get_masked_bits, '255.255.0.255')

  def test_get_address_binary(self):
    """
    Checks the _get_address_binary function.
    """

    test_values = {
      '0.0.0.0': '00000000000000000000000000000000',
      '1.2.3.4': '00000001000000100000001100000100',
      '127.0.0.1': '01111111000000000000000000000001',
      '255.255.255.255': '11111111111111111111111111111111',
      '::': '0' * 128,
      '::1': ('0' * 127) + '1',
      '1::1': '0000000000000001' + ('0' * 111) + '1',
      '2001:db8::ff00:42:8329': '00100000000000010000110110111000000000000000000000000000000000000000000000000000111111110000000000000000010000101000001100101001',
    }

    for test_arg, expected in test_values.items():
      self.assertEqual(expected, stem.util.connection._get_address_binary(test_arg))

    self.assertRaises(ValueError, stem.util.connection._get_address_binary, '')
    self.assertRaises(ValueError, stem.util.connection._get_address_binary, 'blarg')
