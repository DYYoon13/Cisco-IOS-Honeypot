# SPDX-FileCopyrightText: 2026 Honeypot_Playground Contributors
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Cowrie output plugin for the Dashboard web application.

Captures session, command (input + output), and authentication events
into a dedicated SQLite database that the Flask dashboard reads from.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

# Maximum response size stored per command (4 KB)
MAX_RESPONSE_SIZE = 4096


class Output(cowrie.core.output.Output):
    """
    Dashboard SQLite output plugin.

    Writes honeypot events into a separate SQLite database consumed by
    the Flask-based dashboard frontend.
    """

    db: Any

    def start(self) -> None:
        """Initialize the SQLite connection pool and ensure schema exists."""
        db_file = CowrieConfig.get(
            "output_dashboard", "db_file", fallback="var/lib/cowrie/dashboard.db"
        )

        # Ensure the directory exists
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        try:
            self.db = adbapi.ConnectionPool(
                "sqlite3",
                database=db_file,
                check_same_thread=False,
                cp_openfun=lambda conn: conn.execute("PRAGMA journal_mode=TRUNCATE")
            )
        except sqlite3.OperationalError as e:
            log.msg(f"[dashboard] Failed to open database: {e}")
            return

        self.db.start()

        # Create tables if they don't exist
        self._init_schema()

    def _init_schema(self) -> None:
        """Create dashboard tables if they don't already exist."""
        schema_sql = """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            src_ip TEXT NOT NULL,
            start_time DATETIME NOT NULL,
            end_time DATETIME,
            protocol TEXT DEFAULT 'ssh',
            client_version TEXT,
            username TEXT,
            password TEXT
        );

        CREATE TABLE IF NOT EXISTS command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            src_ip TEXT,
            command TEXT NOT NULL,
            response TEXT,
            success BOOLEAN DEFAULT 1,
            cisco_mode TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            src_ip TEXT,
            username TEXT,
            password TEXT,
            success BOOLEAN NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE INDEX IF NOT EXISTS idx_cmd_session ON command_logs(session_id);
        CREATE INDEX IF NOT EXISTS idx_cmd_timestamp ON command_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_cmd_command ON command_logs(command);
        CREATE INDEX IF NOT EXISTS idx_session_ip ON sessions(src_ip);
        CREATE INDEX IF NOT EXISTS idx_session_time ON sessions(start_time);
        CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id);
        CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_attempts(timestamp);
        """
        d = self.db.runInteraction(self._execute_schema, schema_sql)
        d.addErrback(self._sqlerror)

    @staticmethod
    def _execute_schema(txn, sql: str) -> None:
        txn.executescript(sql)

    def stop(self) -> None:
        """Close the database connection pool."""
        if hasattr(self, "db"):
            self.db.close()

    def _sqlerror(self, error) -> None:
        log.err(f"[dashboard] SQLite error: {error}")
        error.printTraceback()

    def _simple_query(self, sql: str, args: tuple) -> None:
        """Run a deferred SQL query, only care about errors."""
        d = self.db.runQuery(sql, args)
        d.addErrback(self._sqlerror)

    @defer.inlineCallbacks
    def write(self, event: dict[str, Any]) -> None:
        eid = event["eventid"]
        log.msg(f"[dashboard] write() called for eventid: {eid}")

        if eid == "cowrie.session.connect":
            self._simple_query(
                "INSERT OR IGNORE INTO sessions (id, src_ip, start_time, protocol) "
                "VALUES (?, ?, ?, ?)",
                (
                    event["session"],
                    event["src_ip"],
                    event["timestamp"],
                    event.get("protocol", "ssh"),
                ),
            )

        elif eid == "cowrie.login.success":
            self._simple_query(
                "INSERT INTO auth_attempts (session_id, timestamp, src_ip, username, password, success) "
                "VALUES (?, ?, ?, ?, ?, 1)",
                (
                    event["session"],
                    event["timestamp"],
                    event.get("src_ip", ""),
                    event.get("username", ""),
                    event.get("password", ""),
                ),
            )
            # Also update the session with username/password
            self._simple_query(
                "UPDATE sessions SET username = ?, password = ? WHERE id = ?",
                (event.get("username", ""), event.get("password", ""), event["session"]),
            )

        elif eid == "cowrie.login.failed":
            self._simple_query(
                "INSERT INTO auth_attempts (session_id, timestamp, src_ip, username, password, success) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                (
                    event["session"],
                    event["timestamp"],
                    event.get("src_ip", ""),
                    event.get("username", ""),
                    event.get("password", ""),
                ),
            )

        elif eid == "cowrie.command.input":
            cisco_mode = event.get("cisco_mode", "user")
            self._simple_query(
                "INSERT INTO command_logs (session_id, timestamp, src_ip, command, success, cisco_mode) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (
                    event["session"],
                    event["timestamp"],
                    event.get("src_ip", ""),
                    event.get("input", ""),
                    cisco_mode,
                ),
            )

        elif eid == "cowrie.command.failed":
            self._simple_query(
                "UPDATE command_logs SET success = 0 "
                "WHERE id = (SELECT id FROM command_logs WHERE session_id = ? ORDER BY id DESC LIMIT 1)",
                (event["session"],),
            )

        elif eid == "cowrie.command.output":
            # Update the most recent command_log entry for this session with the response
            response = event.get("output", "")
            if len(response) > MAX_RESPONSE_SIZE:
                response = response[:MAX_RESPONSE_SIZE] + "\n... [truncated]"
            yield self.db.runQuery(
                "UPDATE command_logs SET response = ? "
                "WHERE id = (SELECT id FROM command_logs WHERE session_id = ? ORDER BY id DESC LIMIT 1)",
                (response, event["session"]),
            )

        elif eid == "cowrie.client.version":
            self._simple_query(
                "UPDATE sessions SET client_version = ? WHERE id = ?",
                (event["version"], event["session"]),
            )

        elif eid == "cowrie.session.closed":
            self._simple_query(
                "UPDATE sessions SET end_time = ? WHERE id = ?",
                (event["timestamp"], event["session"]),
            )
