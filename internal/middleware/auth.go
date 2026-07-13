package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/sourcels/LightyContact/internal/auth"
	"github.com/sourcels/LightyContact/internal/repository"
)

type contextKey string

const UserIDKey contextKey = "userID"

func RequireAuth(authRepo *repository.AuthRepo, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "No Header Authorization", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid format, awaiting Bearer <token>", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		userID, err := auth.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		isBanned, reason, err := authRepo.CheckUserBanStatus(userID)
		if err != nil {
			http.Error(w, "Internal server error checking account status", http.StatusInternalServerError)
			return
		}
		if isBanned {
			http.Error(w, "Your account is banned. Reason: "+reason, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
