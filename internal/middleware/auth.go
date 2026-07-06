package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/sourcels/LightyContact/internal/auth"
)

type contextKey string

const UserIDKey contextKey = "userID"

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Отсутствует заголовок Authorization", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Неверный формат токена. Ожидается Bearer <token>", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		userID, err := auth.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Невалидный или просроченный токен", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, userID)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
