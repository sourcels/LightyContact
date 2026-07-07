package repository

import (
	"database/sql"

	"github.com/sourcels/LightyContact/internal/models"
)

type ChatRepo struct {
	DB *sql.DB
}

func NewChatRepo(db *sql.DB) *ChatRepo {
	return &ChatRepo{DB: db}
}

func (r *ChatRepo) CheckDirectChatExists(user1, user2 string) (string, error) {
	var existingChatID string
	query := `
		SELECT c.id FROM chats c
		JOIN chat_members cm1 ON c.id = cm1.chat_id
		JOIN chat_members cm2 ON c.id = cm2.chat_id
		WHERE c.type = 'direct' AND cm1.user_id = ? AND cm2.user_id = ?
	`
	err := r.DB.QueryRow(query, user1, user2).Scan(&existingChatID)
	return existingChatID, err
}

type ChatMemberInput struct {
	UserID           string
	EncryptedChatKey string
}

func (r *ChatRepo) CreateChat(chatID, chatType, name string, members []ChatMemberInput) error {
	tx, err := r.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO chats (id, type, name) VALUES (?, ?, ?)`, chatID, chatType, name)
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO chat_members (chat_id, user_id, encrypted_chat_key) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, m := range members {
		if _, err := stmt.Exec(chatID, m.UserID, m.EncryptedChatKey); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *ChatRepo) GetUserChats(userID string) ([]models.ChatResponse, error) {
	query := `
		SELECT cm.chat_id, cm.encrypted_chat_key, c.type, c.name 
		FROM chat_members cm
		JOIN chats c ON cm.chat_id = c.id
		WHERE cm.user_id = ?
	`
	rows, err := r.DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chats []models.ChatResponse
	for rows.Next() {
		var cr models.ChatResponse
		var name sql.NullString
		if err := rows.Scan(&cr.ChatID, &cr.EncryptedChatKey, &cr.Type, &name); err != nil {
			return nil, err
		}
		if name.Valid {
			cr.Name = &name.String
		}
		chats = append(chats, cr)
	}
	return chats, nil
}

func (r *ChatRepo) GetChatMemberIDs(chatID string) ([]string, error) {
	rows, err := r.DB.Query(`SELECT user_id FROM chat_members WHERE chat_id = ?`, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err == nil {
			members = append(members, uid)
		}
	}
	return members, nil
}

func (r *ChatRepo) IsChatMember(chatID, userID string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?)`
	err := r.DB.QueryRow(query, chatID, userID).Scan(&exists)
	return exists, err
}

func (r *ChatRepo) GetChatHistory(chatID string, limit int, beforeTimestamp, afterTimestamp int64) ([]models.Message, error) {
	var messages []models.Message

	query := `
		SELECT message_id, chat_id, sender_id, sender_type, chat_type, timestamp, content, iv, file_id 
		FROM messages 
		WHERE chat_id = ?
	`
	args := []interface{}{chatID}

	if beforeTimestamp > 0 {
		query += " AND timestamp < ?"
		args = append(args, beforeTimestamp)
	}
	if afterTimestamp > 0 {
		query += " AND timestamp > ?"
		args = append(args, afterTimestamp)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := r.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var msg models.Message
		var fileID sql.NullString
		var senderType sql.NullString
		var chatType sql.NullString

		err := rows.Scan(
			&msg.MessageID,
			&msg.ChatID,
			&msg.SenderID,
			&senderType,
			&chatType,
			&msg.Timestamp,
			&msg.Content,
			&msg.IV,
			&fileID,
		)
		if err != nil {
			return nil, err
		}

		if fileID.Valid {
			msg.FileID = fileID.String
		}
		if senderType.Valid {
			msg.SenderType = senderType.String
		}
		if chatType.Valid {
			msg.ChatType = chatType.String
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

func (r *ChatRepo) GetChatStatuses(chatID string) ([]models.MessageStatus, error) {
	query := `SELECT message_id, user_id, status, updated_at FROM message_statuses WHERE chat_id = ?`
	rows, err := r.DB.Query(query, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	statuses := make([]models.MessageStatus, 0)
	for rows.Next() {
		var s models.MessageStatus
		s.ChatID = chatID
		if err := rows.Scan(&s.MessageID, &s.UserID, &s.Status, &s.Timestamp); err == nil {
			statuses = append(statuses, s)
		}
	}
	return statuses, nil
}

func (r *ChatRepo) DeleteMessage(messageID, userID string) (string, error) {
	var fileID sql.NullString
	err := r.DB.QueryRow(`SELECT file_id FROM messages WHERE message_id = ? AND sender_id = ?`, messageID, userID).Scan(&fileID)
	if err != nil {
		return "", err
	}

	_, err = r.DB.Exec(`DELETE FROM messages WHERE message_id = ? AND sender_id = ?`, messageID, userID)
	if err != nil {
		return "", err
	}

	_, _ = r.DB.Exec(`DELETE FROM message_statuses WHERE message_id = ?`, messageID)

	if fileID.Valid {
		return fileID.String, nil
	}
	return "", nil
}

func (r *ChatRepo) DeleteChat(chatID, userID string) ([]string, error) {
	// Проверяем права
	isMember, err := r.IsChatMember(chatID, userID)
	if err != nil || !isMember {
		return nil, sql.ErrNoRows
	}

	var fileIDs []string
	rows, err := r.DB.Query(`SELECT file_id FROM messages WHERE chat_id = ? AND file_id IS NOT NULL`, chatID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var fid string
			if err := rows.Scan(&fid); err == nil {
				fileIDs = append(fileIDs, fid)
			}
		}
	}

	tx, err := r.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	tx.Exec(`DELETE FROM message_statuses WHERE chat_id = ?`, chatID)
	tx.Exec(`DELETE FROM messages WHERE chat_id = ?`, chatID)
	tx.Exec(`DELETE FROM chat_members WHERE chat_id = ?`, chatID)
	_, err = tx.Exec(`DELETE FROM chats WHERE id = ?`, chatID)
	if err != nil {
		return nil, err
	}

	return fileIDs, tx.Commit()
}
