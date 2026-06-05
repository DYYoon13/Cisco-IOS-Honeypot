# SPDX-FileCopyrightText: 2026 Honeypot_Playground Contributors
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Cisco IOS CLI engine — command tree, abbreviation resolution, tab completion,
context-sensitive help ('?'), and Cisco-style error formatting.

This module is the central registry used by the shell layer (honeypot.py),
the protocol layer (protocol.py) and the cisco command module (cisco.py)
to make the honeypot behave like a real Cisco IOS CLI.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Command tree — one dict per CLI mode
# ---------------------------------------------------------------------------
# Each entry maps a *full* command keyword to a dict with:
#   "help"  — one-line description shown by '?'
#   "sub"   — (optional) nested dict of sub-commands
#   "args"  — (optional) argument hint string (e.g. "<ip>")
#
# Only keywords that appear in '?' output should be listed.  The actual
# *execution* is still handled by the Command_* classes in cisco.py; this
# tree is only used for abbreviation resolution, tab-completion, and help.
# ---------------------------------------------------------------------------

USER_EXEC_CMDS: dict = {
    "enable": {"help": "Turn on privileged commands"},
    "exit": {"help": "Exit from the EXEC"},
    "logout": {"help": "Exit from the EXEC"},
    "ping": {"help": "Send echo messages", "args": "WORD"},
    "show": {
        "help": "Show running system information",
        "sub": {
            "arp": {"help": "ARP table"},
            "clock": {"help": "Display the system clock"},
            "flash:": {"help": "Display information about flash: file system"},
            "interfaces": {
                "help": "Interface status and configuration",
                "args": "WORD",
            },
            "inventory": {"help": "Show the physical inventory"},
            "ip": {
                "help": "IP information",
                "sub": {
                    "interface": {
                        "help": "IP interface status and configuration",
                        "sub": {
                            "brief": {"help": "Brief summary of IP status and configuration"},
                        },
                    },
                    "route": {"help": "IP routing table"},
                    "arp": {"help": "IP ARP table"},
                    "protocols": {"help": "IP routing protocol information"},
                },
            },
            "logging": {"help": "Show the contents of logging buffers"},
            "processes": {"help": "Active process statistics"},
            "running-config": {"help": "Current operating configuration"},
            "startup-config": {"help": "Contents of startup configuration"},
            "users": {"help": "Display information about terminal lines"},
            "version": {"help": "System hardware and software status"},
        },
    },
    "traceroute": {"help": "Trace route to destination", "args": "WORD"},
    "terminal": {
        "help": "Set terminal line parameters",
        "sub": {
            "length": {"help": "Set number of lines on a screen", "args": "<0-512>"},
            "width": {"help": "Set width of the display terminal", "args": "<0-512>"},
            "monitor": {"help": "Copy debug output to the current terminal line"},
            "no": {"help": "Negate a command or set its defaults"},
        },
    },
}

PRIVILEGED_EXEC_CMDS: dict = {
    "clear": {
        "help": "Reset functions",
        "sub": {
            "arp-cache": {"help": "Clear the entire ARP cache"},
            "counters": {"help": "Clear interface counters", "args": "WORD"},
            "ip": {
                "help": "IP",
                "sub": {
                    "arp": {"help": "Clear IP ARP table"},
                    "route": {"help": "Clear IP routing table", "args": "WORD"},
                },
            },
            "logging": {"help": "Clear logging buffer"},
            "line": {"help": "Reset a terminal line", "args": "<0-16>"},
        },
    },
    "clock": {
        "help": "Manage the system clock",
        "sub": {
            "set": {"help": "Set the time and date", "args": "hh:mm:ss <1-31> MONTH <1993-2035>"},
        },
    },
    "configure": {
        "help": "Enter configuration mode",
        "sub": {
            "terminal": {"help": "Configure from the terminal"},
        },
    },
    "copy": {
        "help": "Copy from one file to another",
        "args": "WORD",
    },
    "debug": {
        "help": "Debugging functions (see also 'undebug')",
        "sub": {
            "all": {"help": "Enable all debugging"},
            "ip": {
                "help": "IP information",
                "sub": {
                    "icmp": {"help": "ICMP transactions"},
                    "packet": {"help": "General IP debugging and target packets"},
                    "routing": {"help": "Routing table events"},
                },
            },
            "ssh": {"help": "Incoming ssh connections"},
        },
    },
    "disable": {"help": "Turn off privileged commands"},
    "enable": {"help": "Turn on privileged commands"},
    "exit": {"help": "Exit from the EXEC"},
    "logout": {"help": "Exit from the EXEC"},
    "no": {
        "help": "Negate a command or set its defaults",
        "sub": {
            "debug": {
                "help": "Debugging functions",
                "sub": {
                    "all": {"help": "Disable all debugging"},
                },
            },
        },
    },
    "ping": {"help": "Send echo messages", "args": "WORD"},
    "reload": {"help": "Halt and perform a cold restart"},
    "show": USER_EXEC_CMDS["show"],  # same tree
    "terminal": USER_EXEC_CMDS["terminal"],
    "traceroute": {"help": "Trace route to destination", "args": "WORD"},
    "undebug": {
        "help": "Disable debugging functions",
        "sub": {
            "all": {"help": "Disable all debugging"},
        },
    },
    "write": {
        "help": "Write running configuration to memory, network, or terminal",
        "sub": {
            "erase": {"help": "Erase the startup configuration"},
            "memory": {"help": "Write to NV memory"},
            "terminal": {"help": "Write to terminal"},
        },
    },
}

CONFIG_CMDS: dict = {
    "banner": {
        "help": "Define a login banner",
        "sub": {
            "motd": {"help": "Set Message of the Day banner"},
            "login": {"help": "Set login banner"},
        },
    },
    "do": {"help": "To run exec commands in config mode"},
    "enable": {
        "help": "Modify enable password parameters",
        "sub": {
            "secret": {"help": "Assign the privileged level secret", "args": "LINE"},
            "password": {"help": "Assign the privileged level password", "args": "LINE"},
        },
    },
    "end": {"help": "Exit from configure mode"},
    "exit": {"help": "Exit from configure mode"},
    "hostname": {"help": "Set system's network name", "args": "WORD"},
    "interface": {
        "help": "Select an interface to configure",
        "sub": {
            "GigabitEthernet": {"help": "GigabitEthernet IEEE 802.3z", "args": "WORD"},
            "Serial": {"help": "Serial interface", "args": "WORD"},
            "Loopback": {"help": "Loopback interface", "args": "<0-2147483647>"},
            "Vlan": {"help": "Catalyst Vlans", "args": "<1-4094>"},
        },
    },
    "ip": {
        "help": "Global IP configuration subcommands",
        "sub": {
            "access-list": {"help": "Named access-list", "args": "WORD"},
            "default-gateway": {"help": "Specify default gateway", "args": "A.B.C.D"},
            "domain-name": {"help": "Define the default domain name", "args": "WORD"},
            "domain": {
                "help": "IP DNS Resolver",
                "sub": {
                    "lookup": {"help": "Enable IP Domain Name System hostname translation"},
                    "name": {"help": "Define the default domain name", "args": "WORD"},
                },
            },
            "name-server": {"help": "Specify address of name server to use", "args": "A.B.C.D"},
            "route": {"help": "Establish static routes", "args": "A.B.C.D A.B.C.D A.B.C.D"},
            "ssh": {
                "help": "Configure SSH",
                "sub": {
                    "version": {"help": "Specify protocol version to be supported", "args": "<1-2>"},
                    "time-out": {"help": "Specify SSH time-out interval", "args": "<1-120>"},
                    "authentication-retries": {"help": "Specify number of authentication retries", "args": "<0-5>"},
                },
            },
        },
    },
    "line": {
        "help": "Configure a terminal line",
        "sub": {
            "console": {"help": "Primary terminal line", "args": "<0-0>"},
            "vty": {"help": "Virtual terminal", "args": "<0-15>"},
            "aux": {"help": "Auxiliary line", "args": "<0-0>"},
        },
    },
    "logging": {
        "help": "Modify message logging facilities",
        "sub": {
            "buffered": {"help": "Set buffered logging parameters"},
            "console": {"help": "Set console logging parameters"},
            "monitor": {"help": "Set terminal line (monitor) logging parameters"},
            "synchronous": {"help": "Synchronized message output"},
        },
    },
    "no": {
        "help": "Negate a command or set its defaults",
    },
    "router": {
        "help": "Enable a routing process",
        "sub": {
            "eigrp": {"help": "Enhanced Interior Gateway Routing Protocol (EIGRP)", "args": "<1-65535>"},
            "ospf": {"help": "Open Shortest Path First (OSPF)", "args": "<1-65535>"},
            "rip": {"help": "Routing Information Protocol (RIP)"},
        },
    },
    "service": {
        "help": "Modify use of network based services",
        "sub": {
            "password-encryption": {"help": "Encrypt system passwords"},
            "timestamps": {"help": "Timestamp debug/log messages"},
        },
    },
    "shutdown": {"help": "Shutdown the selected interface"},
    "snmp-server": {
        "help": "Modify SNMP engine parameters",
        "sub": {
            "community": {"help": "Enable SNMP; set community string and access privs", "args": "WORD"},
            "location": {"help": "Text for mib object sysLocation", "args": "LINE"},
            "contact": {"help": "Text for mib object sysContact", "args": "LINE"},
        },
    },
    "spanning-tree": {
        "help": "Spanning Tree Subsystem",
        "sub": {
            "mode": {"help": "Spanning tree operating mode", "args": "WORD"},
            "vlan": {"help": "VLAN Switch Spanning Tree", "args": "WORD"},
        },
    },
    "username": {"help": "Establish User Name Authentication", "args": "WORD"},
    "vlan": {"help": "Vlan commands", "args": "<1-4094>"},
}

CONFIG_IF_CMDS: dict = {
    "description": {"help": "Interface specific description", "args": "LINE"},
    "do": {"help": "To run exec commands in config mode"},
    "duplex": {
        "help": "Configure duplex operation",
        "sub": {
            "auto": {"help": "Enable AUTO duplex configuration"},
            "full": {"help": "Force full duplex operation"},
            "half": {"help": "Force half-duplex operation"},
        },
    },
    "end": {"help": "Exit from configure mode"},
    "exit": {"help": "Exit from configure mode"},
    "ip": {
        "help": "Interface Internet Protocol config commands",
        "sub": {
            "address": {"help": "Set the IP address of an interface", "args": "A.B.C.D A.B.C.D"},
        },
    },
    "no": {
        "help": "Negate a command or set its defaults",
        "sub": {
            "ip": {
                "help": "Interface Internet Protocol config commands",
                "sub": {
                    "address": {"help": "Remove IP address"},
                },
            },
            "shutdown": {"help": "Bring up the interface"},
        },
    },
    "shutdown": {"help": "Shutdown the selected interface"},
    "speed": {
        "help": "Configure speed operation",
        "sub": {
            "auto": {"help": "Enable AUTO speed configuration"},
            "10": {"help": "Force 10 Mbps operation"},
            "100": {"help": "Force 100 Mbps operation"},
            "1000": {"help": "Force 1000 Mbps operation"},
        },
    },
    "switchport": {
        "help": "Set switching mode characteristics",
        "sub": {
            "access": {
                "help": "Set access mode characteristics of the interface",
                "sub": {
                    "vlan": {"help": "Set VLAN when interface is in access mode", "args": "WORD"},
                },
            },
            "mode": {
                "help": "Set trunking mode of the interface",
                "sub": {
                    "access": {"help": "Set trunking mode to ACCESS unconditionally"},
                    "trunk": {"help": "Set trunking mode to TRUNK unconditionally"},
                },
            },
            "trunk": {
                "help": "Set trunking characteristics when interface is in trunking mode",
                "sub": {
                    "allowed": {
                        "help": "Set allowed VLAN characteristics",
                        "sub": {
                            "vlan": {"help": "Set VLANs allowed", "args": "WORD"},
                        },
                    },
                    "native": {
                        "help": "Set trunking native characteristics",
                        "sub": {
                            "vlan": {"help": "Set native VLAN", "args": "WORD"},
                        },
                    },
                },
            },
        },
    },
}

# Map mode names to their command trees
MODE_TREES: dict[str, dict] = {
    "user": USER_EXEC_CMDS,
    "privileged": PRIVILEGED_EXEC_CMDS,
    "config": CONFIG_CMDS,
    "config-if": CONFIG_IF_CMDS,
}


# ---------------------------------------------------------------------------
# Abbreviation resolution
# ---------------------------------------------------------------------------

def resolve_abbreviation(partial: str, candidates: dict) -> tuple[str | None, list[str]]:
    """
    Resolve an abbreviated keyword against a dict of candidate keywords.

    Returns (matched_full_keyword | None, list_of_matching_keywords).
    - Exact match always wins, even if other keywords share the prefix.
    - If exactly one candidate starts with the partial → return it.
    - If zero or multiple → return None and the list for ambiguity handling.
    """
    if not partial:
        return None, []

    lower = partial.lower()

    # Exact match first
    for key in candidates:
        if key.lower() == lower:
            return key, [key]

    matches = [k for k in candidates if k.lower().startswith(lower)]

    if len(matches) == 1:
        return matches[0], matches
    return None, matches


def resolve_command_tokens(tokens: list[str], mode: str) -> tuple[list[str], str | None, int]:
    """
    Walk the command tree resolving each abbreviated token.

    Returns:
      (resolved_tokens, error_type, error_token_index)

    error_type is one of:
      None          — everything resolved successfully
      "ambiguous"   — a token matched multiple keywords
      "invalid"     — a token matched nothing
      "incomplete"  — command is valid so far but needs more tokens
    """
    tree = MODE_TREES.get(mode, USER_EXEC_CMDS)
    resolved: list[str] = []
    current_level = tree

    for i, tok in enumerate(tokens):
        if current_level is None:
            # We've run past the tree depth — remaining tokens are arguments
            resolved.append(tok)
            continue

        matched, matches = resolve_abbreviation(tok, current_level)

        if matched:
            resolved.append(matched)
            node = current_level[matched]
            current_level = node.get("sub")  # descend or None if leaf
        elif len(matches) > 1:
            # Ambiguous
            resolved.append(tok)
            return resolved, "ambiguous", i
        else:
            # No match — could be an argument to previous command
            # Check if the previous level had "args" hint
            if resolved and current_level is not None:
                # Token doesn't match any subcommand — treat as invalid
                resolved.append(tok)
                return resolved, "invalid", i
            elif not resolved:
                resolved.append(tok)
                return resolved, "invalid", i
            else:
                # Past the tree — just an argument
                resolved.append(tok)
                current_level = None

    return resolved, None, -1


def resolve_command_line(line: str, mode: str) -> tuple[list[str], str | None, int]:
    """
    Convenience wrapper: split a raw command line and resolve abbreviations.
    Returns same tuple as resolve_command_tokens.
    """
    tokens = line.strip().split()
    if not tokens:
        return [], None, -1
    return resolve_command_tokens(tokens, mode)


# ---------------------------------------------------------------------------
# Tab completion
# ---------------------------------------------------------------------------

def complete_command(line: str, mode: str) -> tuple[str | None, list[str]]:
    """
    Cisco-style tab completion.

    Returns (completed_line | None, list_of_candidates).
    - If exactly one match → returns the completed line (full keyword + space)
    - If multiple matches → returns None and the list of candidates
    - If no match → returns None and empty list
    """
    tree = MODE_TREES.get(mode, USER_EXEC_CMDS)
    tokens = line.split()

    if not tokens:
        return None, list(tree.keys())

    # If line ends with a space, we're completing the NEXT token
    trailing_space = line.endswith(" ")

    if trailing_space:
        # Walk the tree for completed tokens, then show candidates at next level
        current = tree
        for tok in tokens:
            if current is None:
                return None, []
            matched, _ = resolve_abbreviation(tok, current)
            if matched:
                current = current[matched].get("sub")
            else:
                return None, []

        if current:
            return None, list(current.keys())
        return None, []
    else:
        # Complete the last token
        partial = tokens[-1]
        prefix_tokens = tokens[:-1]

        # Walk tree for prefix tokens
        current = tree
        resolved_prefix: list[str] = []
        for tok in prefix_tokens:
            if current is None:
                return None, []
            matched, _ = resolve_abbreviation(tok, current)
            if matched:
                resolved_prefix.append(matched)
                current = current[matched].get("sub")
            else:
                return None, []

        if current is None:
            return None, []

        matched, matches = resolve_abbreviation(partial, current)

        if matched and len(matches) == 1:
            # Single match — complete it
            new_line = " ".join(resolved_prefix + [matched]) + " "
            return new_line, [matched]
        elif matches:
            # Multiple matches — find common prefix
            common = _common_prefix([m.lower() for m in matches])
            if len(common) > len(partial):
                new_line = " ".join(resolved_prefix + [common])
                return new_line, matches
            return None, matches
        else:
            return None, []


def _common_prefix(strings: list[str]) -> str:
    """Return the longest common prefix of a list of strings."""
    if not strings:
        return ""
    shortest = min(strings, key=len)
    for i, ch in enumerate(shortest):
        for s in strings:
            if s[i] != ch:
                return shortest[:i]
    return shortest


# ---------------------------------------------------------------------------
# Context-sensitive help ('?')
# ---------------------------------------------------------------------------

def get_help(line: str, mode: str) -> str:
    """
    Generate Cisco-style context-sensitive help output.

    If line is empty or ends with space → list available commands/subcommands.
    If line has a partial token → list matching commands.
    """
    tree = MODE_TREES.get(mode, USER_EXEC_CMDS)
    tokens = line.split()
    trailing_space = line.endswith(" ") if line else True

    if not tokens or (not line.strip()):
        # Top-level help
        return _format_help_list(tree, mode)

    if trailing_space:
        # Walk tree to get next-level commands
        current = tree
        for tok in tokens:
            if current is None:
                return "  <cr>\n"
            matched, matches = resolve_abbreviation(tok, current)
            if matched:
                node = current[matched]
                current = node.get("sub")
            elif len(matches) > 1:
                return "% Ambiguous command:  \"{}\"\n".format(" ".join(tokens))
            else:
                # Token might be an argument — check if parent accepts args
                return "  <cr>\n"

        if current:
            lines: list[str] = []
            for key in sorted(current.keys()):
                lines.append(f"  {key:<20s} {current[key]['help']}")
            lines.append(f"  {'<cr>':<20s}")
            return "\n".join(lines) + "\n"
        else:
            return "  <cr>\n"
    else:
        # Partial token — filter matching commands
        partial = tokens[-1].lower()
        prefix_tokens = tokens[:-1]

        current = tree
        for tok in prefix_tokens:
            if current is None:
                return "% Unrecognized command\n"
            matched, _ = resolve_abbreviation(tok, current)
            if matched:
                current = current[matched].get("sub")
            else:
                return "% Unrecognized command\n"

        if current is None:
            return "  <cr>\n"

        matches = {k: v for k, v in current.items() if k.lower().startswith(partial)}

        if not matches:
            return "% Unrecognized command\n"

        lines = []
        for key in sorted(matches.keys()):
            lines.append(f"  {key:<20s} {matches[key]['help']}")
        return "\n".join(lines) + "\n"


def _format_help_list(tree: dict, mode: str) -> str:
    """Format a top-level help listing."""
    if mode in ("config", "config-if"):
        header = "Configure commands:\n"
    else:
        header = "Exec commands:\n"

    lines: list[str] = [header]
    for key in sorted(tree.keys()):
        lines.append(f"  {key:<20s} {tree[key]['help']}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Cisco-style error formatting
# ---------------------------------------------------------------------------

def format_invalid_input_error(line: str, error_pos: int) -> str:
    """
    Format Cisco IOS "Invalid input detected at '^' marker" error.

    error_pos is the character position in 'line' where the error starts.
    """
    # Build the marker line with spaces up to error_pos, then ^
    marker = " " * error_pos + "^"
    return f"% Invalid input detected at '^' marker.\n\n{line}\n{marker}\n"


def format_ambiguous_error(line: str) -> str:
    """Format Cisco IOS ambiguous command error."""
    return f'% Ambiguous command:  "{line}"\n'


def format_incomplete_error() -> str:
    """Format Cisco IOS incomplete command error."""
    return "% Incomplete command.\n"


def get_error_char_position(tokens: list[str], error_index: int, original_line: str) -> int:
    """
    Calculate character position of a token in the original line.
    This finds the start of the error_index-th token in the original line.
    """
    if error_index <= 0:
        return 0

    parts = original_line.split()
    if error_index >= len(parts):
        return len(original_line)

    pos = 0
    for i in range(error_index):
        pos = original_line.find(parts[i], pos) + len(parts[i])
        # skip whitespace
        while pos < len(original_line) and original_line[pos] == " ":
            pos += 1

    return pos


# ---------------------------------------------------------------------------
# Check if a command needs subcommands (i.e., has "sub" but no "args")
# ---------------------------------------------------------------------------

def command_needs_subcommand(tokens: list[str], mode: str) -> bool:
    """
    Check if the resolved tokens point to a command node that requires
    additional sub-commands (has 'sub' dict but no 'args').
    """
    tree = MODE_TREES.get(mode, USER_EXEC_CMDS)
    current = tree

    for tok in tokens:
        if current is None:
            return False
        matched, _ = resolve_abbreviation(tok, current)
        if matched:
            node = current[matched]
            current = node.get("sub")
            has_args = "args" in node
        else:
            return False

    # If we ended on a node that has sub-commands but no args hint,
    # the command is incomplete
    if current and not has_args:
        return True
    return False
