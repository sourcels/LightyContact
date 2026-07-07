package handlers

import (
	"net/http"

	"github.com/sourcels/LightyContact/internal/middleware"
	"github.com/sourcels/LightyContact/internal/ws"
)

func ConfigureRouter(authHandler *AuthHandler, chatHandler *ChatHandler, hub *ws.Hub) *http.ServeMux {
	mux := http.NewServeMux()

	// --- Invites ---
	mux.HandleFunc("/api/invites/generate", middleware.RequireAuth(authHandler.GenerateInvite))
	mux.HandleFunc("/api/invites/verify", authHandler.VerifyInvite)

	// --- Auth and Users ---
	mux.HandleFunc("/api/register", authHandler.Register)
	mux.HandleFunc("/api/login", authHandler.Login)
	mux.HandleFunc("/api/user/password", middleware.RequireAuth(authHandler.ChangePassword))
	mux.HandleFunc("/api/user/search", middleware.RequireAuth(authHandler.SearchUser))
	mux.HandleFunc("/api/user/delete", middleware.RequireAuth(authHandler.DeleteAccount))

	// --- Chats and Messages ---
	mux.HandleFunc("/api/chat/create", middleware.RequireAuth(chatHandler.CreateChat))
	mux.HandleFunc("/api/chat/history", middleware.RequireAuth(chatHandler.GetHistory))
	mux.HandleFunc("/api/user/chats", middleware.RequireAuth(chatHandler.GetUserChats))
	mux.HandleFunc("/api/chat/statuses", middleware.RequireAuth(chatHandler.GetChatStatuses))

	// --- Deletion ---
	mux.HandleFunc("/api/chat/delete", middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		chatHandler.DeleteChat(hub, w, r)
	}))
	mux.HandleFunc("/api/message/delete", middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		chatHandler.DeleteMessage(hub, w, r)
	}))

	// --- Files ---
	mux.HandleFunc("/api/files/upload", middleware.RequireAuth(chatHandler.UploadFile))
	mux.HandleFunc("/api/files/download", middleware.RequireAuth(chatHandler.DownloadFile))

	// --- Websockets ---
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws.ServeWS(hub, w, r)
	})

	return mux
}
