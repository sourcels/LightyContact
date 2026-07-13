package ws

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/sourcels/LightyContact/internal/models"
)

type ClientMessage struct {
	Client  *Client
	Message []byte
}

type DispatchMessage struct {
	SenderID     string
	Message      []byte
	Participants []string
}

type Hub struct {
	DB         *sql.DB
	Clients    map[string]map[*Client]bool
	Broadcast  chan *ClientMessage
	Dispatch   chan *DispatchMessage
	Register   chan *Client
	Unregister chan *Client
	Disconnect chan string
}

func NewHub(db *sql.DB) *Hub {
	return &Hub{
		DB:         db,
		Broadcast:  make(chan *ClientMessage),
		Dispatch:   make(chan *DispatchMessage),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		Disconnect: make(chan string),
		Clients:    make(map[string]map[*Client]bool),
	}
}

func sendWSError(client *Client, errorMsg string) {
	errPayload, _ := json.Marshal(map[string]string{"error": errorMsg})
	event := models.WSEvent{
		Type:    "error",
		Payload: errPayload,
	}
	response, _ := json.Marshal(event)

	select {
	case client.Send <- response:
	default:
	}
}

func sendWSAck(client *Client, messageID string, timestamp int64) {
	ackPayload, _ := json.Marshal(map[string]interface{}{
		"message_id": messageID,
		"status":     "server_received",
		"timestamp":  timestamp,
	})

	event := models.WSEvent{
		Type:    "ack",
		Payload: ackPayload,
	}
	response, _ := json.Marshal(event)

	select {
	case client.Send <- response:
	default:
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			if h.Clients[client.UserID] == nil {
				h.Clients[client.UserID] = make(map[*Client]bool)
			}
			h.Clients[client.UserID][client] = true
			slog.Info("User connected a new device", "user_id", client.UserID)

		case client := <-h.Unregister:
			if connections, ok := h.Clients[client.UserID]; ok {
				if _, exists := connections[client]; exists {
					delete(connections, client)
					close(client.Send)

					if len(connections) == 0 {
						delete(h.Clients, client.UserID)
						slog.Info("User disconnected", "user_id", client.UserID)
					}
				}
			}

		case userID := <-h.Disconnect:
			if connections, ok := h.Clients[userID]; ok {
				for client := range connections {
					sendWSError(client, "account_banned")
					close(client.Send)
				}
				slog.Info("Force disconnected banned user from WebSockets", "user_id", userID)
			}

		case cMsg := <-h.Broadcast:
			slog.Info("Raw WS message received", "msg", string(cMsg.Message))

			var event models.WSEvent
			if err := json.Unmarshal(cMsg.Message, &event); err != nil {
				slog.Error("Failed to parse WS event", "user_id", cMsg.Client.UserID, "error", err)
				sendWSError(cMsg.Client, "invalid_json_format")
				continue
			}

			var targetChatID string

			switch event.Type {
			case "message":
				var msg models.Message
				if err := json.Unmarshal(event.Payload, &msg); err != nil {
					slog.Error("Failed to parse message payload", "error", err)
					sendWSError(cMsg.Client, "invalid_message_payload")
					continue
				}

				if msg.SenderID != cMsg.Client.UserID {
					slog.Warn("Sender ID spoofing attempt detected", "socket_id", cMsg.Client.UserID, "sender_id", msg.SenderID)
					sendWSError(cMsg.Client, "sender_spoofing_detected")
					continue
				}

				msg.Timestamp = time.Now().Unix()

				targetChatID = msg.ChatID
				var isMember bool
				err := h.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?)`, msg.ChatID, cMsg.Client.UserID).Scan(&isMember)
				if err != nil || !isMember {
					slog.Warn("Access denied: user is not a member of the chat", "user_id", cMsg.Client.UserID, "chat_id", msg.ChatID)
					sendWSError(cMsg.Client, "access_denied")
					continue
				}

				query := `INSERT INTO messages (message_id, chat_id, sender_id, sender_type, chat_type, timestamp, content, iv, file_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
				if _, err = h.DB.Exec(query, msg.MessageID, msg.ChatID, msg.SenderID, msg.SenderType, msg.ChatType, msg.Timestamp, msg.Content, msg.IV, msg.FileID); err != nil {
					slog.Error("Failed to save message to database", "error", err)
					sendWSError(cMsg.Client, "internal_server_error")
					continue
				}

				sendWSAck(cMsg.Client, msg.MessageID, msg.Timestamp)

			case "status":
				var status models.MessageStatus
				if err := json.Unmarshal(event.Payload, &status); err != nil {
					slog.Error("Failed to parse status payload", "error", err)
					sendWSError(cMsg.Client, "invalid_status_payload")
					continue
				}

				if status.UserID != cMsg.Client.UserID {
					slog.Warn("Status sender spoofing attempt detected", "socket_id", cMsg.Client.UserID)
					sendWSError(cMsg.Client, "sender_spoofing_detected")
					continue
				}

				status.Timestamp = time.Now().Unix()

				targetChatID = status.ChatID
				var isMember bool

				err := h.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?)`, status.ChatID, cMsg.Client.UserID).Scan(&isMember)
				if err != nil || !isMember {
					slog.Warn("Access denied: user is not a member of the chat", "user_id", cMsg.Client.UserID, "chat_id", status.ChatID)
					sendWSError(cMsg.Client, "access_denied")
					continue
				}

				upsertQuery := `
					INSERT INTO message_statuses (message_id, user_id, chat_id, status, updated_at) 
					VALUES (?, ?, ?, ?, ?)
					ON CONFLICT(message_id, user_id) 
					DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at;
				`
				if _, err = h.DB.Exec(upsertQuery, status.MessageID, status.UserID, status.ChatID, status.Status, status.Timestamp); err != nil {
					slog.Error("Failed to save message status to database", "error", err)
					sendWSError(cMsg.Client, "internal_server_error")
					continue
				}

				sendWSAck(cMsg.Client, status.MessageID, status.Timestamp)

			default:
				slog.Warn("Unknown WS event type", "type", event.Type)
				sendWSError(cMsg.Client, "unknown_event_type")
				continue
			}

			rows, err := h.DB.Query(`SELECT user_id FROM chat_members WHERE chat_id = ?`, targetChatID)
			if err != nil {
				slog.Error("Failed to fetch chat participants", "error", err)
				return
			}
			defer rows.Close()

			var participants []string
			for rows.Next() {
				var userID string
				if err := rows.Scan(&userID); err == nil {
					participants = append(participants, userID)
				}
			}

			go func(dm *DispatchMessage) {
				h.Dispatch <- dm
			}(&DispatchMessage{
				SenderID:     cMsg.Client.UserID,
				Message:      cMsg.Message,
				Participants: participants,
			})

		case dispatchMsg := <-h.Dispatch:
			for _, participantID := range dispatchMsg.Participants {

				if participantID == dispatchMsg.SenderID {
					continue
				}

				if connections, isOnline := h.Clients[participantID]; isOnline {
					for clientConn := range connections {
						select {
						case clientConn.Send <- dispatchMsg.Message:
						default:
							close(clientConn.Send)
							delete(connections, clientConn)
						}
					}
				}
			}
		}
	}
}
