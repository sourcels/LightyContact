package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sourcels/LightyContact/internal/models"
	"github.com/sourcels/LightyContact/internal/repository"
	"github.com/sourcels/LightyContact/internal/utils"
	"github.com/sourcels/LightyContact/internal/ws"
)

type ChatHandler struct {
	Repo *repository.ChatRepo
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
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		utils.SendError(w, http.StatusBadRequest, "File is too large or format error")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		utils.SendError(w, http.StatusBadRequest, "File not found in request")
		return
	}
	defer file.Close()

	fileID := generateFileID()
	uploadDir := "uploads"
	os.MkdirAll(uploadDir, 0755)

	filePath := filepath.Join(uploadDir, fileID)
	dst, err := os.Create(filePath)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error saving file")
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error writing file")
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{"file_id": fileID})
}

func (h *ChatHandler) DownloadFile(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodGet) {
		return
	}

	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		utils.SendError(w, http.StatusBadRequest, "file_id is required")
		return
	}

	if filepath.Base(fileID) != fileID {
		utils.SendError(w, http.StatusBadRequest, "Invalid file_id")
		return
	}

	filePath := filepath.Join("uploads", fileID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		utils.SendError(w, http.StatusNotFound, "File not found")
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
		utils.SendError(w, http.StatusBadRequest, "chat_id and members are required")
		return
	}

	if req.Type != "direct" && req.Type != "group" {
		utils.SendError(w, http.StatusBadRequest, "Invalid chat type")
		return
	}

	membersInput := make([]repository.ChatMemberInput, 0, len(req.Members))

	for _, member := range req.Members {
		if member.UserID == "system_bot" {
			utils.SendError(w, http.StatusForbidden, "Forbidden to chat with system accounts directly")
			return
		}
		membersInput = append(membersInput, repository.ChatMemberInput{
			UserID:           member.UserID,
			EncryptedChatKey: member.EncryptedChatKey,
		})
	}

	if req.Type == "direct" {
		if len(req.Members) != 2 {
			utils.SendError(w, http.StatusBadRequest, "Direct chat must have exactly 2 members")
			return
		}

		targetUserID := req.Members[0].UserID
		if targetUserID == userID {
			targetUserID = req.Members[1].UserID
		}

		existingChatID, err := h.Repo.CheckDirectChatExists(userID, targetUserID)
		if err == nil && existingChatID != "" {
			utils.SendError(w, http.StatusConflict, "Chat with this user already exists")
			return
		}
	}

	if err := h.Repo.CreateChat(req.ChatID, req.Type, req.Name, membersInput); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error chat creation")
		return
	}

	utils.SendJSON(w, http.StatusCreated, map[string]string{
		"status":  "success",
		"message": "Chat created successfully",
		"chat_id": req.ChatID,
	})
}

func (h *ChatHandler) GetUserChats(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodGet) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	chats, err := h.Repo.GetUserChats(userID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Database error")
		return
	}

	utils.SendJSON(w, http.StatusOK, chats)
}

func (h *ChatHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodGet) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		utils.SendError(w, http.StatusBadRequest, "chat_id is required")
		return
	}

	isMember, err := h.Repo.IsChatMember(chatID, userID)
	if err != nil || !isMember {
		utils.SendError(w, http.StatusForbidden, "Access denied")
		return
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			if parsedLimit > 100 {
				limit = 100
			} else {
				limit = parsedLimit
			}
		}
	}

	var beforeTimestamp, afterTimestamp int64

	if beforeStr := r.URL.Query().Get("before"); beforeStr != "" {
		beforeTimestamp, _ = strconv.ParseInt(beforeStr, 10, 64)
	}
	if afterStr := r.URL.Query().Get("after"); afterStr != "" {
		afterTimestamp, _ = strconv.ParseInt(afterStr, 10, 64)
	}

	messages, err := h.Repo.GetChatHistory(chatID, limit, beforeTimestamp, afterTimestamp)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error getting messages")
		return
	}

	utils.SendJSON(w, http.StatusOK, messages)
}

func (h *ChatHandler) GetChatStatuses(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodGet) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		utils.SendError(w, http.StatusBadRequest, "chat_id is required")
		return
	}

	isMember, err := h.Repo.IsChatMember(chatID, userID)
	if err != nil || !isMember {
		utils.SendError(w, http.StatusForbidden, "Access denied")
		return
	}

	statuses, err := h.Repo.GetChatStatuses(chatID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "DB Error")
		return
	}

	utils.SendJSON(w, http.StatusOK, statuses)
}

func (h *ChatHandler) DeleteMessage(hub *ws.Hub, w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodDelete) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	messageID := r.URL.Query().Get("message_id")
	chatID := r.URL.Query().Get("chat_id")
	if messageID == "" || chatID == "" {
		utils.SendError(w, http.StatusBadRequest, "message_id and chat_id are required")
		return
	}

	participants, err := h.Repo.GetChatMemberIDs(chatID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to fetch chat members")
		return
	}

	fileID, err := h.Repo.DeleteMessage(messageID, userID)
	if err != nil {
		utils.SendError(w, http.StatusForbidden, "Cannot delete message or message not found")
		return
	}

	if fileID != "" {
		os.Remove(filepath.Join("uploads", fileID))
	}

	event := models.WSEvent{
		Type:    "message_deleted",
		Payload: json.RawMessage(`{"message_id":"` + messageID + `", "chat_id":"` + chatID + `"}`),
	}
	eventBytes, _ := json.Marshal(event)

	go func() {
		hub.Dispatch <- &ws.DispatchMessage{
			SenderID:     userID,
			Message:      eventBytes,
			Participants: participants,
		}
	}()

	utils.SendJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *ChatHandler) DeleteChat(hub *ws.Hub, w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodDelete) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	chatID := r.URL.Query().Get("chat_id")
	if chatID == "" {
		utils.SendError(w, http.StatusBadRequest, "chat_id is required")
		return
	}

	participants, err := h.Repo.GetChatMemberIDs(chatID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to fetch chat members")
		return
	}

	isMember := false
	for _, p := range participants {
		if p == userID {
			isMember = true
			break
		}
	}
	if !isMember {
		utils.SendError(w, http.StatusForbidden, "You are not a member of this chat")
		return
	}

	fileIDs, err := h.Repo.DeleteChat(chatID, userID)
	if err != nil {
		utils.SendError(w, http.StatusForbidden, "Cannot delete chat or chat not found")
		return
	}

	for _, fid := range fileIDs {
		os.Remove(filepath.Join("uploads", fid))
	}

	event := models.WSEvent{
		Type:    "chat_deleted",
		Payload: json.RawMessage(`{"chat_id":"` + chatID + `"}`),
	}
	eventBytes, _ := json.Marshal(event)

	go func() {
		hub.Dispatch <- &ws.DispatchMessage{
			SenderID:     userID,
			Message:      eventBytes,
			Participants: participants,
		}
	}()

	utils.SendJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
