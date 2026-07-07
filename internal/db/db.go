package db

import (
	"database/sql"
	"log/slog"

	_ "modernc.org/sqlite"
)

func InitDB(filepath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", filepath)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	_, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")
	if err != nil {
		slog.Error("Failed to configure SQLite PRAGMA", "error", err)
		return nil, err
	}

	if err = createTables(db); err != nil {
		return nil, err
	}

	return db, nil
}

func createTables(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS invites (
		code TEXT PRIMARY KEY,
		created_by TEXT NOT NULL,
		is_used BOOLEAN DEFAULT FALSE,
		created_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		public_key TEXT NOT NULL,
		encrypted_private_key TEXT NOT NULL,
		avatar TEXT,
		status TEXT DEFAULT 'active',
		ban_expires_at INTEGER DEFAULT 0,
		ban_reason TEXT
	);

	CREATE TABLE IF NOT EXISTS chats (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL, -- 'direct' или 'group'
		name TEXT
	);

	CREATE TABLE IF NOT EXISTS chat_members (
		chat_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		encrypted_chat_key TEXT NOT NULL,
		PRIMARY KEY (chat_id, user_id)
	);

	CREATE TABLE IF NOT EXISTS messages (
		message_id TEXT PRIMARY KEY,
		chat_id TEXT NOT NULL,
		sender_id TEXT NOT NULL,
		sender_type TEXT,
		chat_type TEXT,
		timestamp INTEGER NOT NULL,
		content TEXT NOT NULL,
		iv TEXT NOT NULL,
		file_id TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_messages_chat_time ON messages(chat_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);

	CREATE TABLE IF NOT EXISTS message_statuses (
		message_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		chat_id TEXT NOT NULL,
		status TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (message_id, user_id)
	);
	`
	_, err := db.Exec(query)
	return err
}
