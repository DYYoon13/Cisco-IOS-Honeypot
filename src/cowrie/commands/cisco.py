# SPDX-FileCopyrightText: 2026 Honeypot_Playground Contributors
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Cisco IOS command emulation for Cowrie honeypot.

Provides realistic Cisco IOS CLI commands so the honeypot appears to be
a Cisco 2951 router running IOS 15.7(3)M5.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cisco_hostname() -> str:
    """Return the configured hostname (default: Router)."""
    return CowrieConfig.get("honeypot", "hostname", fallback="Router")


def _cisco_uptime(protocol) -> str:
    """Return a human-friendly uptime string like Cisco 'show version'."""
    secs = int(protocol.uptime())
    minutes, secs = divmod(secs, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    weeks, days = divmod(days, 7)
    parts = []
    if weeks:
        parts.append(f"{weeks} week{'s' if weeks != 1 else ''}")
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    return ", ".join(parts) if parts else "0 minutes"


# ---------------------------------------------------------------------------
# show  (dispatcher for all "show ..." sub-commands)
# ---------------------------------------------------------------------------


class Command_show(HoneyPotCommand):
    """Cisco IOS 'show' command dispatcher."""

    SUBCMDS = (
        "version",
        "running-config",
        "startup-config",
        "ip",
        "interfaces",
        "arp",
        "clock",
        "users",
        "logging",
        "flash:",
        "processes",
        "inventory",
        "cdp",
    )

    def call(self) -> None:
        if not self.args:
            self.write("% Incomplete command.\n")
            return

        sub = self.args[0].lower()

        dispatch = {
            "version": self._show_version,
            "running-config": self._show_running_config,
            "startup-config": self._show_startup_config,
            "ip": self._show_ip,
            "interfaces": self._show_interfaces,
            "arp": self._show_arp,
            "clock": self._show_clock,
            "users": self._show_users,
            "logging": self._show_logging,
            "flash:": self._show_flash,
            "processes": self._show_processes,
            "inventory": self._show_inventory,
            "cdp": self._show_cdp,
            "?": self._show_help,
        }

        handler = dispatch.get(sub)
        if handler:
            handler()
        else:
            self.write("% Invalid input detected at '^' marker.\n")

    # -- show version -------------------------------------------------------
    def _show_version(self) -> None:
        hostname = _cisco_hostname()
        uptime = _cisco_uptime(self.protocol)
        serial = "FTX1524" + "".join([str(random.randint(0, 9)) for _ in range(4)])
        self.write(f"""Cisco IOS Software, C2951 Software (C2951-UNIVERSALK9-M), Version 15.7(3)M5, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2020 by Cisco Systems, Inc.
Compiled Thu 09-Jul-20 02:12 by prod_rel_team

ROM: System Bootstrap, Version 15.0(1r)M17, RELEASE SOFTWARE (fc1)

{hostname} uptime is {uptime}
System returned to ROM by power-on
System image file is "flash:c2951-universalk9-mz.SPA.157-3.M5.bin"
Last reload reason: power-on

This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use.

Cisco CISCO2951/K9 (revision 1.0) with 1007616K/49152K bytes of memory.
Processor board ID {serial}
3 Gigabit Ethernet interfaces
1 Serial interface
1 terminal line
1 Virtual Private Network (VPN) Module
DRAM configuration is 72 bits wide with parity enabled.
255K bytes of non-volatile configuration memory.
256M bytes of USB Flash (Read/Write)

Configuration register is 0x2102

""")

    # -- show running-config ------------------------------------------------
    def _show_running_config(self) -> None:
        hostname = _cisco_hostname()
        ip_addr = getattr(self.protocol, "kippoIP", "192.168.1.1")
        self.write(f"""Building configuration...

Current configuration : 2048 bytes
!
! Last configuration change at {datetime.now(timezone.utc).strftime("%H:%M:%S UTC %a %b %d %Y")}
!
version 15.7
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
hostname {hostname}
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
!
no aaa new-model
!
ip cef
no ip domain lookup
ip domain name example.com
!
interface GigabitEthernet0/0
 description WAN Connection
 ip address {ip_addr} 255.255.255.0
 duplex auto
 speed auto
 no shutdown
!
interface GigabitEthernet0/1
 description LAN Connection
 ip address 10.0.0.1 255.255.255.0
 duplex auto
 speed auto
 no shutdown
!
interface GigabitEthernet0/2
 no ip address
 shutdown
!
interface Serial0/0/0
 no ip address
 shutdown
!
ip forward-protocol nd
!
no ip http server
no ip http secure-server
!
ip route 0.0.0.0 0.0.0.0 {ip_addr.rsplit(".", 1)[0]}.254
!
ip access-list extended BLOCK_TELNET
 deny   tcp any any eq telnet
 permit ip any any
!
line con 0
 logging synchronous
line aux 0
line vty 0 4
 login local
 transport input ssh
line vty 5 15
 login local
 transport input ssh
!
ntp server 216.239.35.0
ntp server 216.239.35.4
!
end

""")

    # -- show startup-config ------------------------------------------------
    def _show_startup_config(self) -> None:
        self._show_running_config()

    # -- show ip ... --------------------------------------------------------
    def _show_ip(self) -> None:
        if len(self.args) < 2:
            self.write("% Incomplete command.\n")
            return

        ip_sub = self.args[1].lower()

        if ip_sub in ("interface",):
            self._show_ip_interface_brief()
        elif ip_sub == "route":
            self._show_ip_route()
        elif ip_sub == "arp":
            self._show_arp()
        elif ip_sub == "protocols":
            self._show_ip_protocols()
        else:
            self.write("% Invalid input detected at '^' marker.\n")

    def _show_ip_interface_brief(self) -> None:
        ip_addr = getattr(self.protocol, "kippoIP", "192.168.1.1")
        self.write(
            f"""Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         {ip_addr:<15s} YES NVRAM  up                    up
GigabitEthernet0/1         10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/2         unassigned      YES NVRAM  administratively down down
Serial0/0/0                unassigned      YES NVRAM  administratively down down
"""
        )

    def _show_ip_route(self) -> None:
        ip_addr = getattr(self.protocol, "kippoIP", "192.168.1.1")
        gateway = ip_addr.rsplit(".", 1)[0] + ".254"
        network = ip_addr.rsplit(".", 1)[0] + ".0"
        self.write(
            f"""Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
       ia - IS-IS inter area, * - candidate default, U - per-user static route
       o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP
       a - application route
       + - replicated route, % - next hop override, p - overrides from PfR

Gateway of last resort is {gateway} to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via {gateway}
C     {network}/24 is directly connected, GigabitEthernet0/0
L     {ip_addr}/32 is directly connected, GigabitEthernet0/0
C     10.0.0.0/24 is directly connected, GigabitEthernet0/1
L     10.0.0.1/32 is directly connected, GigabitEthernet0/1
"""
        )

    def _show_ip_protocols(self) -> None:
        self.write("""*** IP Routing is NSF aware ***

Routing Protocol is "application"
  Sending updates every 0 seconds
  Invalid after 0 seconds, hold down 0, flushed after 0
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Maximum path: 32
  Routing for Networks:
  Routing Information Sources:
    Gateway         Distance      Last Update
  Distance: (default is 4)

""")

    # -- show interfaces ----------------------------------------------------
    def _show_interfaces(self) -> None:
        ip_addr = getattr(self.protocol, "kippoIP", "192.168.1.1")
        mac1 = f"0026.{random.randint(0, 0xFFFF):04x}.{random.randint(0, 0xFFFF):04x}"
        mac2 = f"0026.{random.randint(0, 0xFFFF):04x}.{random.randint(0, 0xFFFF):04x}"

        # If a specific interface was requested
        if len(self.args) >= 2 and self.args[1].lower() not in ("?",):
            iface = " ".join(self.args[1:])
            if "0/0" in iface and "0/1" not in iface and "0/2" not in iface:
                self._show_single_interface(
                    "GigabitEthernet0/0", ip_addr, "255.255.255.0", mac1, True
                )
            elif "0/1" in iface:
                self._show_single_interface(
                    "GigabitEthernet0/1", "10.0.0.1", "255.255.255.0", mac2, True
                )
            elif "0/2" in iface:
                self._show_single_interface(
                    "GigabitEthernet0/2", "unassigned", "", mac2, False
                )
            else:
                self.write("% Invalid input detected at '^' marker.\n")
            return

        self._show_single_interface(
            "GigabitEthernet0/0", ip_addr, "255.255.255.0", mac1, True
        )
        self._show_single_interface(
            "GigabitEthernet0/1", "10.0.0.1", "255.255.255.0", mac2, True
        )

    def _show_single_interface(
        self, name: str, ip: str, mask: str, mac: str, up: bool
    ) -> None:
        status = "up" if up else "administratively down"
        proto = "up" if up else "down"
        in_pkts = random.randint(100000, 999999) if up else 0
        out_pkts = random.randint(50000, 500000) if up else 0
        self.write(f"""{name} is {status}, line protocol is {proto}
  Hardware is iGbE, address is {mac} ({mac})
  Internet address is {ip}/{mask if mask else "unassigned"}
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Auto Duplex, Auto Speed, media type is RJ45
  output flow-control is unsupported, input flow-control is unsupported
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:01, output 00:00:02, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  5 minute input rate 1000 bits/sec, 1 packets/sec
  5 minute output rate 1000 bits/sec, 1 packets/sec
     {in_pkts} packets input, {in_pkts * 512} bytes, 0 no buffer
     Received 0 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 watchdog, 0 multicast, 0 pause input
     {out_pkts} packets output, {out_pkts * 256} bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier, 0 pause output
     0 output buffer failures, 0 output buffers swapped out
""")

    # -- show arp -----------------------------------------------------------
    def _show_arp(self) -> None:
        ip_addr = getattr(self.protocol, "kippoIP", "192.168.1.1")
        gateway = ip_addr.rsplit(".", 1)[0] + ".254"
        mac_gw = f"0050.{random.randint(0, 0xFFFF):04x}.{random.randint(0, 0xFFFF):04x}"
        mac_self = (
            f"0026.{random.randint(0, 0xFFFF):04x}.{random.randint(0, 0xFFFF):04x}"
        )
        self.write(f"""Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  {ip_addr:<16s} -          {mac_self}  ARPA   GigabitEthernet0/0
Internet  {gateway:<16s} 12         {mac_gw}  ARPA   GigabitEthernet0/0
Internet  10.0.0.1         -          0026.abcd.ef01  ARPA   GigabitEthernet0/1
""")

    # -- show clock ---------------------------------------------------------
    def _show_clock(self) -> None:
        now = datetime.now(timezone.utc)
        self.write(f"*{now.strftime('%H:%M:%S.000 UTC %a %b %d %Y')}\n")

    # -- show users ---------------------------------------------------------
    def _show_users(self) -> None:
        username = self.protocol.user.username
        client_ip = getattr(self.protocol, "clientIP", "0.0.0.0")
        self.write(f"""    Line       User       Host(s)              Idle       Location
*  0 con 0                idle                 00:00:00
   2 vty 0     {username:<10s} idle                 00:00:00   {client_ip}

  Interface    User               Mode         Idle     Peer Address
""")

    # -- show logging -------------------------------------------------------
    def _show_logging(self) -> None:
        hostname = _cisco_hostname()
        self.write(f"""Syslog logging: enabled (0 messages dropped, 0 messages rate-limited,
                0 flushes, 0 overruns, xml disabled, filtering disabled)

No Active Message Discriminator.

No Inactive Message Discriminator.

    Console logging: level debugging, 47 messages logged, xml disabled,
                     filtering disabled
    Monitor logging: level debugging, 0 messages logged, xml disabled,
                     filtering disabled
    Buffer logging:  level debugging, 47 messages logged, xml disabled,
                     filtering disabled
    Exception Logging: size (8192 bytes)
    Count and timestamp logging messages: disabled
    File logging: disabled
    Persistent logging: disabled

No active filter modules.

Log Buffer (8192 bytes):

*Jun  1 00:00:01.003: %SYS-5-CONFIG_I: Configured from console by {self.protocol.user.username} on vty0
*Jun  1 00:00:02.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up
*Jun  1 00:00:03.456: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to up
*Jun  1 00:00:04.789: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
*Jun  1 00:00:05.012: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up
*Jun  1 00:01:00.345: %SSH-5-ENABLED: SSH 2.0 has been enabled
*Jun  1 00:01:01.678: %SYS-5-RESTART: System restarted --
Cisco IOS Software, C2951 Software (C2951-UNIVERSALK9-M), Version 15.7(3)M5, RELEASE SOFTWARE (fc1)
""")

    # -- show flash: --------------------------------------------------------
    def _show_flash(self) -> None:
        self.write("""-#- --length-- -----date/time------ path
1     95453472 Jun 01 2020 00:00:00 +00:00 c2951-universalk9-mz.SPA.157-3.M5.bin
2         2903 Jun 01 2020 00:01:00 +00:00 cpconfig-2951x.cfg
3          720 Jun 01 2020 00:01:00 +00:00 home.shtml
4       114688 Jun 01 2020 00:01:00 +00:00 home.tar
5         1038 Jun 01 2020 00:01:00 +00:00 vlan.dat

255619072 bytes available (95834112 bytes used)
""")

    # -- show processes -----------------------------------------------------
    def _show_processes(self) -> None:
        self.write("""CPU utilization for five seconds: 3%/0%; one minute: 5%; five minutes: 4%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
   1           4        1637          2  0.00%  0.00%  0.00%   0 Chunk Manager
   2          44        2567         17  0.00%  0.00%  0.00%   0 Load Meter
   3           0           2          0  0.00%  0.00%  0.00%   0 SpanTree Helper
   4        1264        5765        219  0.00%  0.00%  0.00%   0 Check heaps
   5           0           1          0  0.00%  0.00%  0.00%   0 Pool Manager
   6           0           2          0  0.00%  0.00%  0.00%   0 Timers
   7           0           2          0  0.00%  0.00%  0.00%   0 Serial Backgroun
   8           0           1          0  0.00%  0.00%  0.00%   0 OIR Handler
   9          16        5765          2  0.00%  0.00%  0.00%   0 ARP Input
  10       26428       69749        378  0.08%  0.05%  0.01%   0 IP Input
  11        4696        1688       2782  0.00%  0.00%  0.00%   0 CDP Protocol
  12          40        2879         13  0.00%  0.00%  0.00%   0 IP Background
""")

    # -- show inventory -----------------------------------------------------
    def _show_inventory(self) -> None:
        serial = "FTX1524" + "".join([str(random.randint(0, 9)) for _ in range(4)])
        self.write(f"""NAME: "CISCO2951/K9", DESCR: "CISCO2951/K9 chassis, Hw Serial#: {serial}, Hw Revision: V05"
PID: CISCO2951/K9      , VID: V05 , SN: {serial}

NAME: "C2951 Module 0", DESCR: "C2951 Module 0"
PID:                    , VID:     , SN:

""")

    # -- show ? (help) ------------------------------------------------------
    def _show_help(self) -> None:
        self.write("""  arp              ARP table
  cdp              CDP information
  clock            Display the system clock
  flash:           Display information about flash: file system
  interfaces       Interface status and configuration
  inventory        Show the physical inventory
  ip               IP information
  logging          Show the contents of logging buffers
  processes        Active process statistics
  running-config   Current operating configuration
  startup-config   Contents of startup configuration
  users            Display information about terminal lines
  version          System hardware and software status
""")

    # -- show cdp ... -------------------------------------------------------
    def _show_cdp(self) -> None:
        """Dispatch show cdp sub-commands."""
        if len(self.args) < 2:
            self._show_cdp_run()
            return

        sub = self.args[1].lower()
        if sub == "neighbors":
            if len(self.args) >= 3 and self.args[2].lower() == "detail":
                self._show_cdp_neighbors_detail()
            else:
                self._show_cdp_neighbors()
        elif sub == "run":
            self._show_cdp_run()
        elif sub == "interface":
            self._show_cdp_interface()
        else:
            self.write("% Invalid input detected at '^' marker.\n")

    def _show_cdp_run(self) -> None:
        """show cdp — global CDP status."""
        self.write("""Global CDP information:
        Sending CDP packets every 60 seconds
        Sending a holdtime value of 180 seconds
        Sending CDPv2 advertisements is  enabled
""")

    def _show_cdp_neighbors(self) -> None:
        """show cdp neighbors — compact neighbor table (Catalyst 2960 + Aironet AP)."""
        self.write("""Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone,
                  D - Remote, C - CVTA, M - Two-port Mac Relay

Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SW-ACCESS-01     Gig 0/1           138             S I   WS-C2960X Gig 0/1
AP-FLOOR-01      Gig 0/1           112               H   AIR-AP2802I  Gig 0

Total cdp entries displayed : 2
""")

    def _show_cdp_neighbors_detail(self) -> None:
        """show cdp neighbors detail — verbose per-device info."""
        ip_addr = getattr(self.protocol, "kippoIP", "192.168.1.1")
        lan_net = ip_addr.rsplit(".", 1)[0]
        self.write(f"""-------------------------
Device ID: SW-ACCESS-01
Entry address(es):
  IP address: {lan_net}.2
Platform: cisco WS-C2960X-48FPS-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/1
Holdtime : 138 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2021 by Cisco Systems, Inc.
Compiled Thu 29-Apr-21 04:53 by prod_rel_team

advertisement version: 2
VTP Management Domain: ''
Native VLAN: 1
Duplex: full
Management address(es):
  IP address: {lan_net}.2

-------------------------
Device ID: AP-FLOOR-01
Entry address(es):
  IP address: {lan_net}.10
Platform: cisco AIR-AP2802I-A-K9,  Capabilities: Host
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 112 sec

Version :
Cisco AP Software, (ap3g3) Version: 8.10.162.0

advertisement version: 2
Duplex: full
Power drawn: 15.400 Watts
Power request id: 29300, Power management id: 1
Power request levels are:15400 0 0 0 0
Management address(es):
  IP address: {lan_net}.10

""")

    def _show_cdp_interface(self) -> None:
        """show cdp interface — per-interface CDP status."""
        self.write("""GigabitEthernet0/0 is up, line protocol is up
  Encapsulation ARPA
  Sending CDP packets every 60 seconds
  Holdtime is 180 seconds
GigabitEthernet0/1 is up, line protocol is up
  Encapsulation ARPA
  Sending CDP packets every 60 seconds
  Holdtime is 180 seconds
""")


# ---------------------------------------------------------------------------
# enable
# ---------------------------------------------------------------------------



class Command_enable(HoneyPotCommand):
    """Cisco IOS 'enable' command — switch to privileged EXEC mode."""

    def call(self) -> None:
        hostname = _cisco_hostname()
        # Update the prompt to privileged EXEC mode (Router#)
        prompt = f"{hostname}#"
        self.protocol.hostname = hostname
        # Store the cisco_mode on the protocol for other commands to check
        self.protocol.cisco_mode = "privileged"
        # Update the prompt setting so showPrompt() uses it
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell._cisco_prompt = f"{hostname}# "


# ---------------------------------------------------------------------------
# disable
# ---------------------------------------------------------------------------


class Command_disable(HoneyPotCommand):
    """Cisco IOS 'disable' — return to user EXEC mode."""

    def call(self) -> None:
        hostname = _cisco_hostname()
        self.protocol.cisco_mode = "user"
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell._cisco_prompt = f"{hostname}> "


# ---------------------------------------------------------------------------
# configure terminal
# ---------------------------------------------------------------------------


class Command_configure(HoneyPotCommand):
    """Cisco IOS 'configure terminal' — enter global configuration mode."""

    def call(self) -> None:
        hostname = _cisco_hostname()
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "privileged":
            self.write("% Unrecognized command\n")
            return

        if self.args and self.args[0].lower() == "terminal":
            self.write(
                "Enter configuration commands, one per line.  End with CNTL/Z.\n"
            )
            self.protocol.cisco_mode = "config"
            shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
            if shell:
                shell._cisco_prompt = f"{hostname}(config)# "
        else:
            self.write("% Incomplete command.\n")


# ---------------------------------------------------------------------------
# exit / end / logout
# ---------------------------------------------------------------------------


class Command_cisco_exit(HoneyPotCommand):
    """Cisco IOS 'exit' — exit current mode or disconnect."""

    def call(self) -> None:
        hostname = _cisco_hostname()
        mode = getattr(self.protocol, "cisco_mode", "user")
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None

        if mode == "config":
            self.protocol.cisco_mode = "privileged"
            if shell:
                shell._cisco_prompt = f"{hostname}# "
        elif mode == "privileged":
            self.protocol.cisco_mode = "user"
            if shell:
                shell._cisco_prompt = f"{hostname}> "
        else:
            # User EXEC mode — disconnect
            from twisted.internet import error as ierror
            from twisted.python import failure

            stat = failure.Failure(ierror.ProcessDone(status=""))
            self.protocol.terminal.transport.processEnded(stat)
            return


class Command_end(HoneyPotCommand):
    """Cisco IOS 'end' — return to privileged EXEC mode from any config mode."""

    def call(self) -> None:
        hostname = _cisco_hostname()
        self.protocol.cisco_mode = "privileged"
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell._cisco_prompt = f"{hostname}# "


# ---------------------------------------------------------------------------
# write memory / copy running-config startup-config
# ---------------------------------------------------------------------------


class Command_write(HoneyPotCommand):
    """Cisco IOS 'write' command."""

    def call(self) -> None:
        if self.args and self.args[0].lower() == "memory":
            self.write("Building configuration...\n[OK]\n")
        elif self.args and self.args[0].lower() == "terminal":
            # write terminal = show running-config
            cmd = Command_show(self.protocol, "running-config")
            cmd.call()
        elif self.args and self.args[0].lower() == "erase":
            self.write("""Erasing the nvram filesystem will remove all configuration files! Continue? [confirm]
[OK]
Erase of nvram: complete
""")
        elif not self.args:
            self.write("Building configuration...\n[OK]\n")
        else:
            self.write("% Invalid input detected at '^' marker.\n")


# ---------------------------------------------------------------------------
# copy
# ---------------------------------------------------------------------------


class Command_copy(HoneyPotCommand):
    """Cisco IOS 'copy' command stub."""

    def call(self) -> None:
        if len(self.args) >= 2:
            src = self.args[0].lower()
            dst = self.args[1].lower()
            if "running" in src and "startup" in dst:
                self.write(
                    "Destination filename [startup-config]? \n"
                    "Building configuration...\n[OK]\n"
                )
            elif "startup" in src and "running" in dst:
                self.write("Destination filename [running-config]? \n")
            else:
                self.write("% Unknown copy source or destination.\n")
        else:
            self.write("% Incomplete command.\n")


# ---------------------------------------------------------------------------
# reload
# ---------------------------------------------------------------------------


class Command_reload(HoneyPotCommand):
    """Cisco IOS 'reload' command — simulates a router reload."""

    def call(self) -> None:
        self.write("""System configuration has been modified. Save? [yes/no]:
Proceed with reload? [confirm]

*Jun  3 12:00:00.000: %SYS-5-RELOAD: Reload requested by console. Reload Reason: Reload Command.
""")
        # Disconnect the session to simulate the reload
        from twisted.internet import error as ierror
        from twisted.python import failure

        stat = failure.Failure(ierror.ProcessDone(status=""))
        self.protocol.terminal.transport.processEnded(stat)


# ---------------------------------------------------------------------------
# ping  (Cisco-style)
# ---------------------------------------------------------------------------


class Command_cisco_ping(HoneyPotCommand):
    """Cisco IOS 'ping' command — Cisco-style output."""

    import hashlib
    import socket

    def valid_ip(self, address: str) -> bool:
        import socket

        try:
            socket.inet_aton(address)
        except Exception:
            return False
        return True

    def start(self) -> None:
        import hashlib
        import re

        if not self.args:
            self.write("Protocol [ip]: \n")
            self.write("Target IP address: \n")
            self.write("% Incomplete command.\n")
            self.exit()
            return

        host = self.args[0].strip()

        if re.match(r"^[0-9.]+$", host):
            if self.valid_ip(host):
                ip = host
            else:
                self.write("% Unrecognized host or address, or protocol not running.\n")
                self.exit()
                return
        else:
            import hashlib

            s = hashlib.md5(host.encode("utf-8")).hexdigest()
            ip = ".".join([str(int(x, 16)) for x in (s[0:2], s[2:4], s[4:6], s[6:8])])

        # Cisco ping sends 5 probes by default
        count = 5
        success_chars = "!" * count

        self.write(
            f"Type escape sequence to abort.\n"
            f"Sending {count}, 100-byte ICMP Echos to {ip}, timeout is 2 seconds:\n"
            f"{success_chars}\n"
            f"Success rate is 100 percent ({count}/{count}), "
            f"round-trip min/avg/max = 1/4/10 ms\n"
        )
        self.exit()


# ---------------------------------------------------------------------------
# traceroute  (Cisco-style)
# ---------------------------------------------------------------------------


class Command_traceroute(HoneyPotCommand):
    """Cisco IOS 'traceroute' command."""

    def start(self) -> None:
        import hashlib
        import re

        if not self.args:
            self.write("% Incomplete command.\n")
            self.exit()
            return

        host = self.args[0].strip()

        if re.match(r"^[0-9.]+$", host):
            ip = host
        else:
            s = hashlib.md5(host.encode("utf-8")).hexdigest()
            ip = ".".join([str(int(x, 16)) for x in (s[0:2], s[2:4], s[4:6], s[6:8])])

        gw = getattr(self.protocol, "kippoIP", "192.168.1.1")
        gateway = gw.rsplit(".", 1)[0] + ".254"

        self.write(
            f"Type escape sequence to abort.\n"
            f"Tracing the route to {ip}\n"
            f"VRF info: (vrf in name/id, vrf out name/id)\n"
            f"  1 {gateway} 4 msec 4 msec 4 msec\n"
            f"  2 203.0.113.1 12 msec 11 msec 12 msec\n"
            f"  3 198.51.100.1 20 msec 19 msec 20 msec\n"
            f"  4 {ip} 28 msec 27 msec 28 msec\n"
        )
        self.exit()


# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------


class Command_terminal(HoneyPotCommand):
    """Cisco IOS 'terminal' command (e.g. terminal length 0)."""

    def call(self) -> None:
        # Silently accept — no actual paging to configure
        pass


# ---------------------------------------------------------------------------
# no  (stub for config mode)
# ---------------------------------------------------------------------------


class Command_no(HoneyPotCommand):
    """Cisco IOS 'no' prefix — stub that accepts any config negation."""

    def call(self) -> None:
        # In config mode, silently accept. Outside config mode, error.
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")


# ---------------------------------------------------------------------------
# hostname  (config mode command)
# ---------------------------------------------------------------------------


class Command_hostname(HoneyPotCommand):
    """Cisco IOS 'hostname' config command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if self.args:
            new_hostname = self.args[0]
            self.protocol.hostname = new_hostname
            shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
            if shell:
                shell._cisco_prompt = f"{new_hostname}(config)# "
        else:
            self.write("% Incomplete command.\n")


# ---------------------------------------------------------------------------
# interface  (config mode stub)
# ---------------------------------------------------------------------------


class Command_interface(HoneyPotCommand):
    """Cisco IOS 'interface' config command — stub."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if self.args:
            hostname = _cisco_hostname()
            iface_short = self.args[0][:2]
            self.protocol.cisco_mode = "config-if"
            shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
            if shell:
                shell._cisco_prompt = f"{hostname}(config-if)# "
        else:
            self.write("% Incomplete command.\n")


# ---------------------------------------------------------------------------
# ip (config mode stub)
# ---------------------------------------------------------------------------


class Command_ip(HoneyPotCommand):
    """Cisco IOS 'ip' config command — stub that silently accepts."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config", "config-if"):
            self.write("% Invalid input detected at '^' marker.\n")


# ---------------------------------------------------------------------------
# ? (help)
# ---------------------------------------------------------------------------


class Command_question(HoneyPotCommand):
    """Cisco IOS '?' — context-sensitive help (fallback for Enter-based '?')."""

    def call(self) -> None:
        from cowrie.commands import cisco_cli

        mode = getattr(self.protocol, "cisco_mode", "user")
        help_text = cisco_cli.get_help("", mode)
        self.write(help_text)


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------


class Command_clear(HoneyPotCommand):
    """Cisco IOS 'clear' command stubs."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("privileged",):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        sub = self.args[0].lower()
        if sub in ("counters", "counter"):
            self.write("Clear \"show interface\" counters on all interfaces [confirm]\n")
        elif sub in ("arp-cache", "arp"):
            pass  # silently succeed
        elif sub == "logging":
            self.write("Clear logging buffer [confirm]\n")
        elif sub == "ip":
            pass  # silently succeed
        elif sub == "line":
            if len(self.args) >= 2:
                self.write(" [OK]\n")
            else:
                self.write("% Incomplete command.\n")
        else:
            self.write("% Invalid input detected at '^' marker.\n")


# ---------------------------------------------------------------------------
# debug / undebug
# ---------------------------------------------------------------------------


class Command_debug(HoneyPotCommand):
    """Cisco IOS 'debug' command stub."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "privileged":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        sub = " ".join(self.args).lower()
        if "all" in sub:
            self.write(
                "This may severely impact network performance. Continue? (yes/[no]): \n"
                "All possible debugging has been turned on\n"
            )
        else:
            debug_type = " ".join(self.args)
            self.write(f"{debug_type} debugging is on\n")


class Command_undebug(HoneyPotCommand):
    """Cisco IOS 'undebug' command stub."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "privileged":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        sub = " ".join(self.args).lower()
        if "all" in sub:
            self.write("All possible debugging has been turned off\n")
        else:
            debug_type = " ".join(self.args)
            self.write(f"{debug_type} debugging is off\n")


# ---------------------------------------------------------------------------
# clock set
# ---------------------------------------------------------------------------


class Command_clock(HoneyPotCommand):
    """Cisco IOS 'clock' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "privileged":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if self.args and self.args[0].lower() == "set":
            if len(self.args) >= 5:
                # clock set hh:mm:ss day month year — silently accept
                pass
            else:
                self.write("% Incomplete command.\n")
        else:
            self.write("% Incomplete command.\n")


# ---------------------------------------------------------------------------
# shutdown (config-if mode)
# ---------------------------------------------------------------------------


class Command_shutdown(HoneyPotCommand):
    """Cisco IOS 'shutdown' command for interface config mode."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config-if", "config"):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Simulates shutting down the interface
        self.write(
            "*Jun  1 00:00:10.123: %LINK-5-CHANGED: Interface GigabitEthernet0/0, "
            "changed state to administratively down\n"
            "*Jun  1 00:00:11.123: %LINEPROTO-5-UPDOWN: Line protocol on Interface "
            "GigabitEthernet0/0, changed state to down\n"
        )


# ---------------------------------------------------------------------------
# do (run exec commands from config mode)
# ---------------------------------------------------------------------------


class Command_do(HoneyPotCommand):
    """Cisco IOS 'do' command — run exec commands from config mode."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config", "config-if"):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        # Resolve abbreviations in privileged exec mode
        from cowrie.commands import cisco_cli

        resolved, err, _ = cisco_cli.resolve_command_tokens(list(self.args), "privileged")
        if err:
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Put the resolved command in the pending queue for the shell to process
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell.cmdpending.append(resolved)


# ---------------------------------------------------------------------------
# description (config-if mode)
# ---------------------------------------------------------------------------


class Command_description(HoneyPotCommand):
    """Cisco IOS 'description' command for interface config."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config-if",):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept any description


# ---------------------------------------------------------------------------
# duplex / speed (config-if mode stubs)
# ---------------------------------------------------------------------------


class Command_duplex(HoneyPotCommand):
    """Cisco IOS 'duplex' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config-if",):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        # Silently accept


class Command_speed(HoneyPotCommand):
    """Cisco IOS 'speed' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config-if",):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# switchport (config-if mode stub)
# ---------------------------------------------------------------------------


class Command_switchport(HoneyPotCommand):
    """Cisco IOS 'switchport' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config-if",):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept all switchport configs


# ---------------------------------------------------------------------------
# line (config mode stub)
# ---------------------------------------------------------------------------


class Command_line(HoneyPotCommand):
    """Cisco IOS 'line' config command — enters line config sub-mode."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        hostname = _cisco_hostname()
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell._cisco_prompt = f"{hostname}(config-line)# "
        self.protocol.cisco_mode = "config"  # keep in config (simplified)


# ---------------------------------------------------------------------------
# service (config mode stub)
# ---------------------------------------------------------------------------


class Command_service(HoneyPotCommand):
    """Cisco IOS 'service' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept all service configs


# ---------------------------------------------------------------------------
# router (config mode stub)
# ---------------------------------------------------------------------------


class Command_router(HoneyPotCommand):
    """Cisco IOS 'router' command — enters router config sub-mode."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        hostname = _cisco_hostname()
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell._cisco_prompt = f"{hostname}(config-router)# "


# ---------------------------------------------------------------------------
# banner (config mode stub)
# ---------------------------------------------------------------------------


class Command_banner(HoneyPotCommand):
    """Cisco IOS 'banner' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# username (config mode stub)
# ---------------------------------------------------------------------------


class Command_username(HoneyPotCommand):
    """Cisco IOS 'username' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# vlan (config mode stub)
# ---------------------------------------------------------------------------


class Command_vlan(HoneyPotCommand):
    """Cisco IOS 'vlan' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        if not self.args:
            self.write("% Incomplete command.\n")
            return
        hostname = _cisco_hostname()
        shell = self.protocol.cmdstack[0] if self.protocol.cmdstack else None
        if shell:
            shell._cisco_prompt = f"{hostname}(config-vlan)# "


# ---------------------------------------------------------------------------
# access-list (config mode stub)
# ---------------------------------------------------------------------------


class Command_access_list(HoneyPotCommand):
    """Cisco IOS 'access-list' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# snmp-server (config mode stub)
# ---------------------------------------------------------------------------


class Command_snmp_server(HoneyPotCommand):
    """Cisco IOS 'snmp-server' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# spanning-tree (config mode stub)
# ---------------------------------------------------------------------------


class Command_spanning_tree(HoneyPotCommand):
    """Cisco IOS 'spanning-tree' command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode != "config":
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# logging (config mode stub — separate from show logging)
# ---------------------------------------------------------------------------


class Command_logging_config(HoneyPotCommand):
    """Cisco IOS 'logging' config command."""

    def call(self) -> None:
        mode = getattr(self.protocol, "cisco_mode", "user")
        if mode not in ("config", "config-line"):
            self.write("% Invalid input detected at '^' marker.\n")
            return
        # Silently accept


# ---------------------------------------------------------------------------
# Register all commands
# ---------------------------------------------------------------------------

commands["show"] = Command_show
commands["enable"] = Command_enable
commands["disable"] = Command_disable
commands["configure"] = Command_configure
commands["exit"] = Command_cisco_exit
commands["logout"] = Command_cisco_exit
commands["end"] = Command_end
commands["write"] = Command_write
commands["copy"] = Command_copy
commands["reload"] = Command_reload
commands["ping"] = Command_cisco_ping
commands["/bin/ping"] = Command_cisco_ping
commands["traceroute"] = Command_traceroute
commands["terminal"] = Command_terminal
commands["no"] = Command_no
commands["hostname"] = Command_hostname
commands["interface"] = Command_interface
commands["ip"] = Command_ip
commands["?"] = Command_question

# New commands for enhanced realism
commands["clear"] = Command_clear
commands["debug"] = Command_debug
commands["undebug"] = Command_undebug
commands["clock"] = Command_clock
commands["shutdown"] = Command_shutdown
commands["do"] = Command_do
commands["description"] = Command_description
commands["duplex"] = Command_duplex
commands["speed"] = Command_speed
commands["switchport"] = Command_switchport
commands["line"] = Command_line
commands["service"] = Command_service
commands["router"] = Command_router
commands["banner"] = Command_banner
commands["username"] = Command_username
commands["vlan"] = Command_vlan
commands["access-list"] = Command_access_list
commands["snmp-server"] = Command_snmp_server
commands["spanning-tree"] = Command_spanning_tree
commands["logging"] = Command_logging_config

