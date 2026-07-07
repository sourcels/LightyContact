package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"time"
)

func EnsureInitialInvite(db *sql.DB) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		slog.Error("Failed to check users count", "error", err)
		return
	}

	if count == 0 {
		var inviteCount int
		db.QueryRow("SELECT COUNT(*) FROM invites WHERE created_by = 'system' AND is_used = FALSE").Scan(&inviteCount)

		if inviteCount == 0 {
			bytes := make([]byte, 16)
			rand.Read(bytes)
			code := hex.EncodeToString(bytes)
			timestamp := time.Now().Unix()

			_, err = db.Exec(`
				INSERT INTO invites (code, created_by, is_used, created_at) 
				VALUES (?, ?, ?, ?)`,
				code, "system", false, timestamp,
			)
			if err != nil {
				slog.Error("Failed to create initial invite", "error", err)
				return
			}

			slog.Warn("==================================================")
			slog.Warn("DATABASE IS EMPTY. NO USERS FOUND.")
			slog.Warn("GENERATED INITIAL INVITE CODE: " + code)
			slog.Warn("Use this code to register the first user!")
			slog.Warn("==================================================")
		} else {
			slog.Info("Waiting for the first user to register using the system invite.")
		}
	}
}
