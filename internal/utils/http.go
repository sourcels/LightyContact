package utils

import (
	"encoding/json"
	"net/http"

	"github.com/sourcels/LightyContact/internal/middleware"
)

func SendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func SendJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func CheckMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		SendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return false
	}
	return true
}

func GetUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok {
		SendError(w, http.StatusUnauthorized, "Ошибка авторизации")
		return "", false
	}
	return userID, true
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		SendError(w, http.StatusBadRequest, "Invalid JSON format")
		return false
	}
	return true
}
