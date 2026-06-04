# SPDX-FileCopyrightText: 2026 Honeypot_Playground Contributors
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Flask backend for the Cisco IOS Honeypot Dashboard.

Serves the static frontend and provides REST API endpoints
for querying session, command, and authentication data from
the SQLite database written by the dashboard_output.py plugin.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Flask, g, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")

# Database path — override via DASHBOARD_DB_FILE environment variable
DB_FILE = os.environ.get("DASHBOARD_DB_FILE", "var/lib/cowrie/dashboard.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def get_db() -> sqlite3.Connection:
    """Open a database connection per-request and cache it in Flask's `g`."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=TRUNCATE")
    return g.db


@app.teardown_appcontext
def close_db(exc: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create schema if the database file does not exist yet."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    if os.path.exists(schema_path):
        db = sqlite3.connect(DB_FILE)
        with open(schema_path) as f:
            db.executescript(f.read())
        db.close()


def _parse_time_filters() -> tuple[str | None, str | None]:
    """Extract ``from`` and ``to`` query params as ISO timestamps."""
    t_from = request.args.get("from")
    t_to = request.args.get("to")
    return t_from, t_to


def _pagination() -> tuple[int, int]:
    """Extract ``limit`` and ``offset`` query params."""
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))
    return limit, offset


# ---------------------------------------------------------------------------
# Static file serving
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------------------
# API — Overview Stats
# ---------------------------------------------------------------------------


@app.route("/api/stats/overview")
def stats_overview():
    db = get_db()
    t_from, t_to = _parse_time_filters()
    ip_filter = request.args.get("ip")

    # Build WHERE clauses
    where, params = [], []
    if t_from:
        where.append("start_time >= ?")
        params.append(t_from)
    if t_to:
        where.append("start_time <= ?")
        params.append(t_to)
    if ip_filter:
        where.append("src_ip = ?")
        params.append(ip_filter)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    total_sessions = db.execute(
        f"SELECT COUNT(*) FROM sessions{where_sql}", params
    ).fetchone()[0]

    unique_ips = db.execute(
        f"SELECT COUNT(DISTINCT src_ip) FROM sessions{where_sql}", params
    ).fetchone()[0]

    # Total commands (join with sessions for filtering)
    if where:
        cmd_where = where_sql.replace("start_time", "s.start_time").replace(
            "src_ip", "s.src_ip"
        )
        total_commands = db.execute(
            f"SELECT COUNT(*) FROM command_logs c JOIN sessions s ON c.session_id = s.id{cmd_where}",
            params,
        ).fetchone()[0]
    else:
        total_commands = db.execute("SELECT COUNT(*) FROM command_logs").fetchone()[0]

    # Active sessions (no end_time)
    active_sessions = db.execute(
        "SELECT COUNT(*) FROM sessions WHERE end_time IS NULL"
    ).fetchone()[0]

    # Today's sessions
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_sessions = db.execute(
        "SELECT COUNT(*) FROM sessions WHERE start_time >= ?", (today,)
    ).fetchone()[0]

    return jsonify(
        {
            "total_sessions": total_sessions,
            "unique_ips": unique_ips,
            "total_commands": total_commands,
            "active_sessions": active_sessions,
            "today_sessions": today_sessions,
        }
    )


# ---------------------------------------------------------------------------
# API — Command Statistics
# ---------------------------------------------------------------------------


@app.route("/api/stats/commands")
def stats_commands():
    db = get_db()
    limit, _ = _pagination()
    limit = min(limit, 20)

    rows = db.execute(
        "SELECT command, COUNT(*) as cnt FROM command_logs "
        "GROUP BY command ORDER BY cnt DESC LIMIT ?",
        (limit,),
    ).fetchall()

    return jsonify([{"command": r["command"], "count": r["cnt"]} for r in rows])


# ---------------------------------------------------------------------------
# API — Timeline
# ---------------------------------------------------------------------------


@app.route("/api/stats/timeline")
def stats_timeline():
    db = get_db()
    granularity = request.args.get("granularity", "hour")  # hour | day
    days_back = int(request.args.get("days", 7))

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    if granularity == "day":
        fmt = "%Y-%m-%d"
    else:
        fmt = "%Y-%m-%dT%H:00:00"

    rows = db.execute(
        "SELECT strftime(?, start_time) as period, COUNT(*) as cnt "
        "FROM sessions WHERE start_time >= ? "
        "GROUP BY period ORDER BY period",
        (fmt, cutoff),
    ).fetchall()

    return jsonify([{"period": r["period"], "count": r["cnt"]} for r in rows])


# ---------------------------------------------------------------------------
# API — Top IPs
# ---------------------------------------------------------------------------


@app.route("/api/stats/top-ips")
def stats_top_ips():
    db = get_db()
    limit, _ = _pagination()
    limit = min(limit, 20)

    rows = db.execute(
        "SELECT src_ip, COUNT(*) as cnt, "
        "MIN(start_time) as first_seen, MAX(start_time) as last_seen "
        "FROM sessions GROUP BY src_ip ORDER BY cnt DESC LIMIT ?",
        (limit,),
    ).fetchall()

    return jsonify(
        [
            {
                "ip": r["src_ip"],
                "count": r["cnt"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in rows
        ]
    )


# ---------------------------------------------------------------------------
# API — Sessions List
# ---------------------------------------------------------------------------


@app.route("/api/sessions")
def list_sessions():
    db = get_db()
    limit, offset = _pagination()
    t_from, t_to = _parse_time_filters()
    ip_filter = request.args.get("ip")

    where, params = [], []
    if t_from:
        where.append("start_time >= ?")
        params.append(t_from)
    if t_to:
        where.append("start_time <= ?")
        params.append(t_to)
    if ip_filter:
        where.append("src_ip = ?")
        params.append(ip_filter)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    rows = db.execute(
        f"SELECT * FROM sessions{where_sql} ORDER BY start_time DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()

    total = db.execute(f"SELECT COUNT(*) FROM sessions{where_sql}", params).fetchone()[
        0
    ]

    return jsonify(
        {
            "sessions": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


# ---------------------------------------------------------------------------
# API — Session Detail
# ---------------------------------------------------------------------------


@app.route("/api/sessions/<session_id>")
def session_detail(session_id: str):
    db = get_db()

    session = db.execute(
        "SELECT * FROM sessions WHERE id = ?", (session_id,)
    ).fetchone()

    if session is None:
        return jsonify({"error": "Session not found"}), 404

    commands = db.execute(
        "SELECT * FROM command_logs WHERE session_id = ? ORDER BY timestamp",
        (session_id,),
    ).fetchall()

    auth = db.execute(
        "SELECT * FROM auth_attempts WHERE session_id = ? ORDER BY timestamp",
        (session_id,),
    ).fetchall()

    return jsonify(
        {
            "session": dict(session),
            "commands": [dict(c) for c in commands],
            "auth_attempts": [dict(a) for a in auth],
        }
    )


# ---------------------------------------------------------------------------
# API — Recent Commands (Live Feed)
# ---------------------------------------------------------------------------


@app.route("/api/commands/recent")
def recent_commands():
    db = get_db()
    limit, _ = _pagination()

    rows = db.execute(
        "SELECT c.*, s.src_ip as session_ip FROM command_logs c "
        "JOIN sessions s ON c.session_id = s.id "
        "ORDER BY c.timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()

    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# API — Auth Attempts
# ---------------------------------------------------------------------------


@app.route("/api/auth-attempts")
def auth_attempts():
    db = get_db()
    limit, offset = _pagination()

    rows = db.execute(
        "SELECT * FROM auth_attempts ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()

    total = db.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0]

    # Top username/password combos
    combos = db.execute(
        "SELECT username, password, COUNT(*) as cnt, "
        "SUM(CASE WHEN success THEN 1 ELSE 0 END) as success_count "
        "FROM auth_attempts GROUP BY username, password "
        "ORDER BY cnt DESC LIMIT 20"
    ).fetchall()

    return jsonify(
        {
            "attempts": [dict(r) for r in rows],
            "total": total,
            "top_combos": [dict(c) for c in combos],
        }
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Ensure DB directory exists
    db_dir = os.path.dirname(DB_FILE)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        os.chmod(db_dir, 0o777)  # Allow cowrie to write WAL files

    init_db()

    # Ensure database is writable by cowrie
    if os.path.exists(DB_FILE):
        os.chmod(DB_FILE, 0o666)

    app.run(host="0.0.0.0", port=5001, debug=True)
