package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sourcels/LightyContact/internal/auth"
	"github.com/sourcels/LightyContact/internal/middleware"
	"github.com/sourcels/LightyContact/internal/models"
	"github.com/sourcels/LightyContact/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	DB *sql.DB
}

type RegisterRequest struct {
	ID                  string `json:"id"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Avatar              string `json:"avatar"`
	InviteCode          string `json:"invite_code"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	SessionToken        string `json:"session_token"`
	PublicKey           string `json:"public_key"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

func generateInviteCode() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (h *AuthHandler) GenerateInvite(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	if userID != "_root" {
		utils.SendError(w, http.StatusForbidden, "You are not allowed to send invites")
		return
	}

	code := generateInviteCode()
	timestamp := time.Now().Unix()

	_, err := h.DB.Exec(`INSERT INTO invites (code, created_by, is_used, created_at) VALUES (?, ?, FALSE, ?)`, code, userID, timestamp)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error creating invite")
		return
	}

	utils.SendJSON(w, http.StatusCreated, map[string]string{
		"invite_code": code,
		"link":        "?invite=" + code,
	})
}

func (h *AuthHandler) VerifyInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error": "Code was not sent"}`, http.StatusBadRequest)
		return
	}

	var isUsed bool
	err := h.DB.QueryRow(`SELECT is_used FROM invites WHERE code = ?`, code).Scan(&isUsed)
	if err == sql.ErrNoRows {
		http.Error(w, `{"error": "Invite didn't found"}`, http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, `{"error": "DB Error"}`, http.StatusInternalServerError)
		return
	}

	if isUsed {
		http.Error(w, `{"error": "Invite already used"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "valid"}`))
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	var req RegisterRequest
	if !utils.DecodeJSON(w, r, &req) {
		return
	}

	if req.InviteCode == "" {
		utils.SendError(w, http.StatusForbidden, "Invite code is needed")
		return
	}

	if req.ID == "" || req.Username == "" || req.Password == "" || req.PublicKey == "" || req.EncryptedPrivateKey == "" {
		utils.SendError(w, http.StatusBadRequest, "All fields are required")
		return
	}

	if err := utils.ValidateUsername(req.Username); err != nil {
		utils.SendError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := utils.ValidatePassword(req.Password); err != nil {
		utils.SendError(w, http.StatusBadRequest, err.Error())
		return
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE invites SET is_used = TRUE WHERE code = ? AND is_used = FALSE`, req.InviteCode)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "DB Error while Invite check")
		return
	}
	if rowsAffected, _ := res.RowsAffected(); rowsAffected == 0 {
		utils.SendError(w, http.StatusForbidden, "Invite is invalid or already used")
		return
	}

	query := `INSERT INTO users (id, username, password_hash, public_key, encrypted_private_key, avatar) VALUES (?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(query, req.ID, req.Username, string(hashedToken), req.PublicKey, req.EncryptedPrivateKey, req.Avatar)
	if err != nil {
		utils.SendError(w, http.StatusConflict, "Пользователь с таким именем уже существует")
		return
	}

	tx.Commit()
	utils.SendJSON(w, http.StatusCreated, map[string]string{"status": "success"})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req LoginRequest
	if !utils.DecodeJSON(w, r, &req) {
		return
	}

	var u models.User
	query := `SELECT id, username, password_hash, public_key, encrypted_private_key FROM users WHERE username = ?`
	err := h.DB.QueryRow(query, req.Username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.PublicKey, &u.EncryptedPrivateKey)
	if err == sql.ErrNoRows {
		utils.SendError(w, http.StatusUnauthorized, "Invalid Username or Password")
		return
	} else if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		utils.SendError(w, http.StatusUnauthorized, "Invalid Username or Password")
		return
	}

	sessionToken, err := auth.GenerateToken(u.ID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error token generation")
		return
	}

	utils.SendJSON(w, http.StatusOK, LoginResponse{
		SessionToken:        sessionToken,
		PublicKey:           u.PublicKey,
		EncryptedPrivateKey: u.EncryptedPrivateKey,
	})
}

type ChangePasswordRequest struct {
	OldPassword         string `json:"old_password"`
	NewPassword         string `json:"new_password"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok {
		http.Error(w, `{"error": "Error auth"}`, http.StatusInternalServerError)
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if err := utils.ValidatePassword(req.NewPassword); err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	var currentHash string
	err := h.DB.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&currentHash)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword)); err != nil {
		http.Error(w, `{"error": "Incorrect old password"}`, http.StatusUnauthorized)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error": "Internal error"}`, http.StatusInternalServerError)
		return
	}

	query := `UPDATE users SET password_hash = ?, encrypted_private_key = ? WHERE id = ?`
	_, err = h.DB.Exec(query, string(newHash), req.EncryptedPrivateKey, userID)
	if err != nil {
		http.Error(w, `{"error": "Update password error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Password changed successfully",
	})
}

type SearchUserResponse struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
	Avatar    string `json:"avatar"`
}

func (h *AuthHandler) SearchUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	var user SearchUserResponse

	query := `
        SELECT id, username, public_key, avatar FROM users 
        WHERE username = ? 
        AND username NOT LIKE '\_%' 
        AND username NOT LIKE '%_bot'
    `

	err := h.DB.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.PublicKey, &user.Avatar)

	if err == sql.ErrNoRows {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
