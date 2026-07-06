package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sourcels/LightyContact/internal/middleware"
	"github.com/sourcels/LightyContact/internal/models"
	"github.com/sourcels/LightyContact/internal/utils"
)

type ChatHandler struct {
	DB *sql.DB
}

type CreateChatRequest struct {
	ChatID  string `json:"chat_id"`
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Members []struct {
		UserID           string `json:"user_id"`
		EncryptedChatKey string `json:"encrypted_chat_key"`
	} `json:"members"`
}

func generateFileID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (h *ChatHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, "Файл слишком большой или ошибка формата", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Файл не найден в запросе", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileID := generateFileID()
	uploadDir := "uploads"
	os.MkdirAll(uploadDir, 0755)

	filePath := filepath.Join(uploadDir, fileID)
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Ошибка сохранения файла", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Ошибка записи файла", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"file_id": fileID})
}

func (h *ChatHandler) DownloadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		http.Error(w, "file_id обязателен", http.StatusBadRequest)
		return
	}

	if filepath.Base(fileID) != fileID {
		http.Error(w, "Неверный file_id", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join("uploads", fileID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Файл не найден", http.StatusNotFound)
		return
	}

	http.ServeFile(w, r, filePath)
}

func (h *ChatHandler) CreateChat(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	var req CreateChatRequest
	if !utils.DecodeJSON(w, r, &req) {
		return
	}

	if req.ChatID == "" || len(req.Members) == 0 {
		utils.SendError(w, http.StatusBadRequest, "chat_id и список members обязательны")
		return
	}

	if req.Type != "direct" && req.Type != "group" {
		utils.SendError(w, http.StatusBadRequest, "Неверный тип чата")
		return
	}

	isRoot := userID == "_root"
	for _, member := range req.Members {
		if (member.UserID == "_root" || member.UserID == "system_bot") && !isRoot {
			utils.SendError(w, http.StatusForbidden, "Forbidden to chat with system accounts")
			return
		}
	}

	if req.Type == "direct" && len(req.Members) == 2 {
		var targetUserID string
		for _, m := range req.Members {
			if m.UserID != userID {
				targetUserID = m.UserID
				break
			}
		}

		var existingChatID string
		checkQuery := `
			SELECT c.id FROM chats c
			JOIN chat_members cm1 ON c.id = cm1.chat_id
			JOIN chat_members cm2 ON c.id = cm2.chat_id
			WHERE c.type = 'direct' AND cm1.user_id = ? AND cm2.user_id = ?
		`
		err := h.DB.QueryRow(checkQuery, userID, targetUserID).Scan(&existingChatID)
		if err == nil && existingChatID != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error":"Chat with this user already exists", "chat_id":"` + existingChatID + `"}`))
			return
		}
	}

	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	chatQuery := `INSERT INTO chats (id, type, name) VALUES (?, ?, ?)`
	_, err = tx.Exec(chatQuery, req.ChatID, req.Type, req.Name)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Error chat creation", http.StatusInternalServerError)
		return
	}

	membersQuery := `INSERT OR IGNORE INTO chat_members (chat_id, user_id, encrypted_chat_key) VALUES (?, ?, ?)`
	stmt, err := tx.Prepare(membersQuery)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Ошибка подготовки запроса участников", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	for _, member := range req.Members {
		_, err := stmt.Exec(req.ChatID, member.UserID, member.EncryptedChatKey)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Ошибка сохранения участников (возможно, дубликат)", http.StatusConflict)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Transaction error")
		return
	}

	utils.SendJSON(w, http.StatusCreated, map[string]string{
		"status":  "success",
		"message": "Chat created successfully",
		"chat_id": req.ChatID,
	})
}

func (h *ChatHandler) GetUserChats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok {
		http.Error(w, "Ошибка авторизации", http.StatusInternalServerError)
		return
	}

	query := `
		SELECT cm.chat_id, cm.encrypted_chat_key, c.type, c.name 
		FROM chat_members cm
		JOIN chats c ON cm.chat_id = c.id
		WHERE cm.user_id = ?
	`
	rows, err := h.DB.Query(query, userID)
	if err != nil {
		http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var chats []models.ChatResponse
	for rows.Next() {
		var chat models.ChatResponse
		var chatName sql.NullString

		if err := rows.Scan(&chat.ChatID, &chat.EncryptedChatKey, &chat.Type, &chatName); err != nil {
			continue
		}

		if chatName.Valid {
			chat.Name = &chatName.String
		}

		chats = append(chats, chat)
	}

	if chats == nil {
		chats = make([]models.ChatResponse, 0)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chats)
}

func (h *ChatHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok {
		http.Error(w, "Ошибка авторизации", http.StatusInternalServerError)
		return
	}

	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		http.Error(w, "chat_id обязателен", http.StatusBadRequest)
		return
	}

	var exists bool
	err := h.DB.QueryRow(`SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?`, chatID, userID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, "Доступ запрещен: вы не участник этого чата", http.StatusForbidden)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				limit = 100
			} else {
				limit = parsedLimit
			}
		}
	}

	beforeStr := r.URL.Query().Get("before")
	afterStr := r.URL.Query().Get("after")

	var query string
	var rows *sql.Rows
	var errQuery error

	if afterStr != "" {
		afterTimestamp, err := strconv.ParseInt(afterStr, 10, 64)
		if err != nil {
			http.Error(w, "Неверный формат параметра after", http.StatusBadRequest)
			return
		}

		query = `
			SELECT message_id, chat_id, sender_id, sender_type, chat_type, timestamp, content, iv, file_id 
			FROM messages 
			WHERE chat_id = ? AND timestamp > ? 
			ORDER BY timestamp ASC 
			LIMIT ?
		`
		rows, errQuery = h.DB.Query(query, chatID, afterTimestamp, limit)

	} else if beforeStr != "" {
		beforeTimestamp, err := strconv.ParseInt(beforeStr, 10, 64)
		if err != nil {
			http.Error(w, "Неверный формат параметра before", http.StatusBadRequest)
			return
		}

		query = `
			SELECT message_id, chat_id, sender_id, sender_type, chat_type, timestamp, content, iv, file_id 
			FROM messages 
			WHERE chat_id = ? AND timestamp < ? 
			ORDER BY timestamp DESC 
			LIMIT ?
		`
		rows, errQuery = h.DB.Query(query, chatID, beforeTimestamp, limit)

	} else {
		query = `
			SELECT message_id, chat_id, sender_id, sender_type, chat_type, timestamp, content, iv, file_id 
			FROM messages
			WHERE chat_id = ?
			ORDER BY timestamp DESC
			LIMIT ?
		`
		rows, errQuery = h.DB.Query(query, chatID, limit)
	}

	if errQuery != nil {
		http.Error(w, "Error getting messages", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	messages := make([]models.Message, 0)
	for rows.Next() {
		var msg models.Message
		var fileID sql.NullString

		if err := rows.Scan(
			&msg.MessageID,
			&msg.ChatID,
			&msg.SenderID,
			&msg.SenderType,
			&msg.ChatType,
			&msg.Timestamp,
			&msg.Content,
			&msg.IV,
			&fileID,
		); err != nil {
			continue
		}

		if fileID.Valid {
			msg.FileID = fileID.String
		}

		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func (h *ChatHandler) GetChatStatuses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok {
		http.Error(w, "Ошибка авторизации", http.StatusInternalServerError)
		return
	}

	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		http.Error(w, "chat_id обязателен", http.StatusBadRequest)
		return
	}

	var exists bool
	err := h.DB.QueryRow(`SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?`, chatID, userID).Scan(&exists)
	if err != nil || !exists {
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}

	query := `SELECT message_id, user_id, status, updated_at FROM message_statuses WHERE chat_id = ?`
	rows, err := h.DB.Query(query, chatID)
	if err != nil {
		http.Error(w, "Ошибка БД", http.StatusInternalServerError)
		return
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}
