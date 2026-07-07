package utils

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

func StartFileGC(db *sql.DB, uploadDir string, interval time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			slog.Info("Starting Garbage Collector (Files & Invites)...")

			expiredTimestamp := time.Now().Unix() - (7 * 24 * 3600)
			res, err := db.Exec("DELETE FROM invites WHERE created_at < ? AND is_used = FALSE", expiredTimestamp)
			if err != nil {
				slog.Error("GC: Failed to delete expired invites", "error", err)
			} else {
				invitesDeleted, _ := res.RowsAffected()
				if invitesDeleted > 0 {
					slog.Info("GC: Cleaned up expired invites", "deleted_count", invitesDeleted)
				}
			}

			validFiles := make(map[string]bool)

			msgRows, err := db.Query(`SELECT file_id FROM messages WHERE file_id IS NOT NULL`)
			if err != nil {
				slog.Error("GC: Failed to fetch file IDs from messages", "error", err)
				continue
			}
			for msgRows.Next() {
				var fileID string
				if err := msgRows.Scan(&fileID); err == nil {
					validFiles[fileID] = true
				}
			}
			msgRows.Close()

			avatarRows, err := db.Query(`SELECT avatar FROM users WHERE avatar IS NOT NULL AND avatar != ''`)
			if err != nil {
				slog.Error("GC: Failed to fetch avatars from users", "error", err)
			} else {
				for avatarRows.Next() {
					var avatar string
					if err := avatarRows.Scan(&avatar); err == nil {
						validFiles[avatar] = true
					}
				}
				avatarRows.Close()
			}

			entries, err := os.ReadDir(uploadDir)
			if err != nil {
				slog.Error("GC: Failed to read upload directory", "error", err)
				continue
			}

			deletedCount := 0
			now := time.Now()

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				info, err := entry.Info()
				if err != nil {
					continue
				}

				fileName := entry.Name()

				if !validFiles[fileName] && now.Sub(info.ModTime()) > time.Hour {
					filePath := filepath.Join(uploadDir, fileName)
					if err := os.Remove(filePath); err != nil {
						slog.Warn("GC: Failed to delete orphaned file", "file", fileName, "error", err)
					} else {
						deletedCount++
					}
				}
			}

			slog.Info("File Garbage Collector finished", "deleted_files", deletedCount)
		}
	}()
}
