package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sourcels/LightyContact/internal/auth"
	"github.com/sourcels/LightyContact/internal/models"
	"github.com/sourcels/LightyContact/internal/repository"
	"github.com/sourcels/LightyContact/internal/utils"
	"github.com/sourcels/LightyContact/internal/ws"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	Repo *repository.AuthRepo
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
	Role                string `json:"role"`
}

type ChangePasswordRequest struct {
	OldPassword         string `json:"old_password"`
	NewPassword         string `json:"new_password"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
}

func (h *AuthHandler) GenerateInvite(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	role, err := h.Repo.GetUserRole(userID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to verify user role")
		return
	}

	if role != "admin" {
		count, err := h.Repo.GetInviteCountLastWeek(userID)
		if err != nil {
			utils.SendError(w, http.StatusInternalServerError, "Database error checking limits")
			return
		}

		if count >= 1 {
			utils.SendError(w, http.StatusTooManyRequests, "Weekly invite limit reached (max 1 per week)")
			return
		}
	}

	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal error")
		return
	}
	code := hex.EncodeToString(bytes)
	timestamp := time.Now().Unix()

	err = h.Repo.CreateInvite(code, userID, timestamp)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to generate invite code")
		return
	}

	utils.SendJSON(w, http.StatusCreated, map[string]string{
		"status":      "success",
		"invite_code": code,
	})
}

func (h *AuthHandler) VerifyInvite(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodGet) {
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		utils.SendError(w, http.StatusBadRequest, "Code was not sent")
		return
	}

	isUsed, err := h.Repo.IsInviteUsed(code)
	if err != nil {
		utils.SendError(w, http.StatusNotFound, "Invite not found or DB Error")
		return
	}

	if isUsed {
		utils.SendError(w, http.StatusConflict, "Invite already used")
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{"status": "valid"})
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

	user := models.User{
		ID:                  req.ID,
		Username:            req.Username,
		PasswordHash:        string(hashedToken),
		PublicKey:           req.PublicKey,
		EncryptedPrivateKey: req.EncryptedPrivateKey,
	}

	if err := h.Repo.RegisterUserWithInvite(user, req.InviteCode, req.Avatar); err != nil {
		utils.SendError(w, http.StatusConflict, "Invalid invite, or username already exists")
		return
	}

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

	u, err := h.Repo.GetUserByUsername(req.Username)
	if err != nil {
		utils.SendError(w, http.StatusUnauthorized, "Invalid Username or Password")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		utils.SendError(w, http.StatusUnauthorized, "Invalid Username or Password")
		return
	}

	role, _ := h.Repo.GetUserRole(u.ID)

	sessionToken, err := auth.GenerateToken(u.ID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error token generation")
		return
	}

	utils.SendJSON(w, http.StatusOK, LoginResponse{
		SessionToken:        sessionToken,
		PublicKey:           u.PublicKey,
		EncryptedPrivateKey: u.EncryptedPrivateKey,
		Role:                role,
	})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPut) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	var req ChangePasswordRequest
	if !utils.DecodeJSON(w, r, &req) {
		return
	}

	if err := utils.ValidatePassword(req.NewPassword); err != nil {
		utils.SendError(w, http.StatusBadRequest, err.Error())
		return
	}

	currentHash, err := h.Repo.GetPasswordHash(userID)
	if err != nil {
		utils.SendError(w, http.StatusNotFound, "User not found")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword)); err != nil {
		utils.SendError(w, http.StatusUnauthorized, "Incorrect old password")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal error")
		return
	}

	if err := h.Repo.UpdatePassword(userID, string(newHash), req.EncryptedPrivateKey); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Update password error")
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Password changed successfully",
	})
}

func (h *AuthHandler) SearchUser(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodGet) {
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		utils.SendError(w, http.StatusBadRequest, "username is required")
		return
	}

	user, err := h.Repo.SearchUser(username)
	if err != nil {
		utils.SendError(w, http.StatusNotFound, "User not found")
		return
	}

	utils.SendJSON(w, http.StatusOK, user)
}

func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodDelete) {
		return
	}

	userID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	avatarFileName, err := h.Repo.DeleteUser(userID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if avatarFileName != "" {
		uploadDir := "uploads"
		fullPath := filepath.Join(uploadDir, avatarFileName)

		if err := os.Remove(fullPath); err != nil {
			slog.Error("Failed to delete avatar file from disk", "path", fullPath, "error", err)
		}
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Account and avatar deleted successfully",
	})
}

type BanUserRequest struct {
	UserID   string `json:"user_id"`
	Duration int64  `json:"duration_seconds"`
	Reason   string `json:"reason"`
}

type UnbanUserRequest struct {
	UserID string `json:"user_id"`
}

func (h *AuthHandler) BanUser(hub *ws.Hub, w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	currentUserID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	role, err := h.Repo.GetUserRole(currentUserID)
	if err != nil || role != "admin" {
		utils.SendError(w, http.StatusForbidden, "Only admin can ban users")
		return
	}

	var req BanUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserID == "" {
		utils.SendError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	err = h.Repo.BanUser(req.UserID, req.Duration, req.Reason)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "User has been banned successfully",
	})

	hub.Disconnect <- req.UserID
}

func (h *AuthHandler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	if !utils.CheckMethod(w, r, http.MethodPost) {
		return
	}

	currentUserID, ok := utils.GetUserID(w, r)
	if !ok {
		return
	}

	role, err := h.Repo.GetUserRole(currentUserID)
	if err != nil || role != "admin" {
		utils.SendError(w, http.StatusForbidden, "Only admin can unban users")
		return
	}

	var req UnbanUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.Repo.UnbanUser(req.UserID)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to unban user")
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "User has been unbanned successfully",
	})
}
