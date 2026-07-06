package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sourcels/LightyContact/internal/auth"
	"github.com/sourcels/LightyContact/internal/config"
	"github.com/sourcels/LightyContact/internal/db"
	"github.com/sourcels/LightyContact/internal/handlers"
	"github.com/sourcels/LightyContact/internal/middleware"
	"github.com/sourcels/LightyContact/internal/ws"
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
			// 3. Нет ни в .env, ни в БД -> генерируем!
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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	cfg := config.Load()

	if cfg.JWTSecret == "" {
		slog.Error("Critical error: JWT_SECRET environment variable is not set")
		os.Exit(1)
	}

	if err := auth.Init(cfg.JWTSecret); err != nil {
		slog.Error("Failed to initialize auth package", "error", err)
		os.Exit(1)
	}

	database, err := db.InitDB(cfg.DBPath)
	if err != nil {
		slog.Error("Critical database error", "error", err)
		os.Exit(1)
	}

	slog.Info("Successfully connected to SQLite. Tables are ready.")

	authHandler := &handlers.AuthHandler{DB: database}
	chatHandler := &handlers.ChatHandler{DB: database}

	hub := ws.NewHub(database)
	go hub.Run()

	corsMiddleware := middleware.EnableCORS(cfg.AllowedOrigin)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/invites/generate", corsMiddleware(middleware.RequireAuth(authHandler.GenerateInvite)))
	mux.HandleFunc("/api/invites/verify", corsMiddleware(authHandler.VerifyInvite)) // Без авторизации!
	mux.HandleFunc("/api/register", corsMiddleware(authHandler.Register))
	mux.HandleFunc("/api/login", corsMiddleware(authHandler.Login))
	mux.HandleFunc("/api/user/password", corsMiddleware(middleware.RequireAuth(authHandler.ChangePassword)))
	mux.HandleFunc("/api/chat/create", corsMiddleware(middleware.RequireAuth(chatHandler.CreateChat)))
	mux.HandleFunc("/api/chat/history", corsMiddleware(middleware.RequireAuth(chatHandler.GetHistory)))
	mux.HandleFunc("/api/user/chats", corsMiddleware(middleware.RequireAuth(chatHandler.GetUserChats)))
	mux.HandleFunc("/api/files/upload", corsMiddleware(middleware.RequireAuth(chatHandler.UploadFile)))
	mux.HandleFunc("/api/files/download", corsMiddleware(middleware.RequireAuth(chatHandler.DownloadFile)))
	mux.HandleFunc("/api/chat/statuses", corsMiddleware(middleware.RequireAuth(chatHandler.GetChatStatuses)))
	mux.HandleFunc("/api/user/search", corsMiddleware(middleware.RequireAuth(authHandler.SearchUser)))
	mux.HandleFunc("/ws", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		ws.ServeWS(hub, w, r)
	}))

	address := ":" + cfg.Port
	srv := &http.Server{
		Addr:    address,
		Handler: mux,
	}

	go func() {
		slog.Info("Server is starting", "address", address, "allowed_origin", cfg.AllowedOrigin)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	slog.Info("Shutdown signal received, shutting down server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	if err := database.Close(); err != nil {
		slog.Error("Error closing database connection", "error", err)
	}

	slog.Info("Server exited properly")
}
