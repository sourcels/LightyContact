package handlers

import (
	"net/http"

	"github.com/sourcels/LightyContact/internal/middleware"
	"github.com/sourcels/LightyContact/internal/ws"
)

func ConfigureRouter(authHandler *AuthHandler, chatHandler *ChatHandler, hub *ws.Hub) *http.ServeMux {
	mux := http.NewServeMux()
	authRepo := authHandler.Repo

	// --- Admin Ban endpoints ---
	mux.HandleFunc("/api/admin/user/ban", middleware.RequireAuth(authRepo, func(w http.ResponseWriter, r *http.Request) {
		authHandler.BanUser(hub, w, r)
	}))
	mux.HandleFunc("/api/admin/user/unban", middleware.RequireAuth(authRepo, authHandler.UnbanUser))

	// --- Invites ---
	mux.HandleFunc("/api/invites/generate", middleware.RequireAuth(authRepo, authHandler.GenerateInvite))
	mux.HandleFunc("/api/invites/verify", authHandler.VerifyInvite)

	// --- Auth and Users ---
	mux.HandleFunc("/api/register", authHandler.Register)
	mux.HandleFunc("/api/login", authHandler.Login)
	mux.HandleFunc("/api/user/password", middleware.RequireAuth(authRepo, authHandler.ChangePassword))
	mux.HandleFunc("/api/user/search", middleware.RequireAuth(authRepo, authHandler.SearchUser))
	mux.HandleFunc("/api/user/delete", middleware.RequireAuth(authRepo, authHandler.DeleteAccount))

	// --- Chats and Messages ---
	mux.HandleFunc("/api/chat/create", middleware.RequireAuth(authRepo, chatHandler.CreateChat))
	mux.HandleFunc("/api/chat/history", middleware.RequireAuth(authRepo, chatHandler.GetHistory))
	mux.HandleFunc("/api/user/chats", middleware.RequireAuth(authRepo, chatHandler.GetUserChats))
	mux.HandleFunc("/api/chat/statuses", middleware.RequireAuth(authRepo, chatHandler.GetChatStatuses))

	// --- Deletion ---
	mux.HandleFunc("/api/chat/delete", middleware.RequireAuth(authRepo, func(w http.ResponseWriter, r *http.Request) {
		chatHandler.DeleteChat(hub, w, r)
	}))
	mux.HandleFunc("/api/message/delete", middleware.RequireAuth(authRepo, func(w http.ResponseWriter, r *http.Request) {
		chatHandler.DeleteMessage(hub, w, r)
	}))

	// --- Files ---
	mux.HandleFunc("/api/files/upload", middleware.RequireAuth(authRepo, chatHandler.UploadFile))
	mux.HandleFunc("/api/files/download", middleware.RequireAuth(authRepo, chatHandler.DownloadFile))

	// --- Websockets ---
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ws.ServeWS(hub, w, r)
	})

	return mux
}
