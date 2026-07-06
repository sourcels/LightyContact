package models

import (
	"encoding/json"
)

type User struct {
	ID                  string `json:"id"`
	Username            string `json:"username"`
	PasswordHash        string `json:"-"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

type Chat struct {
	ID   string  `json:"id"`
	Type string  `json:"type"`
	Name *string `json:"name,omitempty"`
}

type ChatResponse struct {
	ChatID           string  `json:"chat_id"`
	Type             string  `json:"type"`
	Name             *string `json:"name,omitempty"`
	EncryptedChatKey string  `json:"encrypted_chat_key"`
	TargetUsername   string  `json:"target_username,omitempty"`
}

type Message struct {
	MessageID  string `json:"message_id"`
	ChatID     string `json:"chat_id"`
	SenderID   string `json:"sender_id"`
	SenderType string `json:"sender_type"`
	ChatType   string `json:"chat_type"`
	Timestamp  int64  `json:"timestamp"`
	Content    string `json:"content"`
	IV         string `json:"iv"`
	FileID     string `json:"file_id,omitempty"`
}

type WSEvent struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type MessageStatus struct {
	MessageID string `json:"message_id"`
	ChatID    string `json:"chat_id"`
	UserID    string `json:"user_id"`
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}
