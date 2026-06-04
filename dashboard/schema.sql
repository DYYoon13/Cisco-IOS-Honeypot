-- Cisco IOS Honeypot Dashboard — Database Schema
-- SQLite database for storing honeypot session and command data

-- Sessions: เก็บข้อมูล connection แต่ละครั้ง
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

-- Command Logs: เก็บคำสั่ง + response คู่กัน
CREATE TABLE IF NOT EXISTS command_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    src_ip TEXT,
    command TEXT NOT NULL,
    response TEXT,              -- ผลลัพธ์ที่ระบบตอบกลับ (truncated at 4KB)
    success BOOLEAN DEFAULT 1,
    cisco_mode TEXT,            -- user/privileged/config
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Auth Attempts: เก็บ login attempts
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

-- Indexes for Dashboard query performance
CREATE INDEX IF NOT EXISTS idx_cmd_session ON command_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_cmd_timestamp ON command_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_cmd_command ON command_logs(command);
CREATE INDEX IF NOT EXISTS idx_session_ip ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_session_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id);
CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_attempts(timestamp);
