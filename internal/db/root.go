package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"

	"golang.org/x/crypto/bcrypt"
)

func InitRootUser(db *sql.DB, envPassword string) {
	rootID := "_root"
	var dbHash string

	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", rootID).Scan(&dbHash)
	rootExists := (err != sql.ErrNoRows)

	var passwordToSet string
	needUpdateHash := false

	if envPassword != "" {
		passwordToSet = envPassword
		if !rootExists || bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(envPassword)) != nil {
			needUpdateHash = true
		}
	} else {
		if rootExists {
			slog.Info("Root user loaded using database password")
		} else {
			bytes := make([]byte, 8)
			rand.Read(bytes)
			passwordToSet = hex.EncodeToString(bytes)
			needUpdateHash = true

			slog.Warn("==================================================")
			slog.Warn("INITIALIZING _root ACCOUNT FOR THE FIRST TIME!")
			slog.Warn("AUTO-GENERATED PASSWORD: " + passwordToSet)
			slog.Warn("Please save this password or add it to .env (ROOT_PASSWORD)")
			slog.Warn("==================================================")
		}
	}

	if needUpdateHash {
		hashed, _ := bcrypt.GenerateFromPassword([]byte(passwordToSet), bcrypt.DefaultCost)

		if !rootExists {
			_, err = db.Exec(`
				INSERT INTO users (id, username, password_hash, public_key, encrypted_private_key, avatar) 
				VALUES (?, ?, ?, ?, ?, ?)`,
				rootID, "_root", string(hashed), "root_pub", "root_priv", "",
			)
			if err != nil {
				slog.Error("Failed to create _root user", "error", err)
			}
		} else {
			_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(hashed), rootID)
			if err != nil {
				slog.Error("Failed to update _root password", "error", err)
			} else {
				slog.Info("Root user password synchronized with .env")
			}
		}
	}
}
