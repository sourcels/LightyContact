package main

import (
	"context"
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
	"github.com/sourcels/LightyContact/internal/repository"
	"github.com/sourcels/LightyContact/internal/utils"
	"github.com/sourcels/LightyContact/internal/ws"
)

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

	db.InitRootUser(database, cfg.RootPassword)

	uploadDir := "./uploads"
	os.MkdirAll(uploadDir, os.ModePerm)
	utils.StartFileGC(database, uploadDir, 12*time.Hour)

	authRepo := repository.NewAuthRepo(database)
	chatRepo := repository.NewChatRepo(database)

	authHandler := &handlers.AuthHandler{Repo: authRepo}
	chatHandler := &handlers.ChatHandler{Repo: chatRepo}

	hub := ws.NewHub(database)
	go hub.Run()

	mux := handlers.ConfigureRouter(authHandler, chatHandler, hub)

	corsMiddleware := middleware.EnableCORS(cfg.AllowedOrigin)
	globalHandlerWithCORS := corsMiddleware(http.HandlerFunc(mux.ServeHTTP))

	address := ":" + cfg.Port
	srv := &http.Server{
		Addr:    address,
		Handler: globalHandlerWithCORS, // Используем обертку CORS для всех запросов
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
