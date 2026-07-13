package repository

import (
	"database/sql"
	"errors"
	"time"

	"github.com/sourcels/LightyContact/internal/models"
)

type AuthRepo struct {
	DB *sql.DB
}

func NewAuthRepo(db *sql.DB) *AuthRepo {
	return &AuthRepo{DB: db}
}

func (r *AuthRepo) CreateInvite(code, createdBy string, timestamp int64) error {
	_, err := r.DB.Exec(`INSERT INTO invites (code, created_by, is_used, created_at) VALUES (?, ?, FALSE, ?)`, code, createdBy, timestamp)
	return err
}

func (r *AuthRepo) GetInviteCountLastWeek(userID string) (int, error) {
	var count int
	oneWeekAgo := time.Now().Unix() - (7 * 24 * 3600) // 7 дней в секундах
	query := `SELECT COUNT(*) FROM invites WHERE created_by = ? AND created_at > ?`
	err := r.DB.QueryRow(query, userID, oneWeekAgo).Scan(&count)
	return count, err
}

func (r *AuthRepo) IsInviteUsed(code string) (bool, error) {
	var isUsed bool
	query := `SELECT is_used FROM invites WHERE code = ?`
	err := r.DB.QueryRow(query, code).Scan(&isUsed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, errors.New("invite code not found")
		}
		return false, err
	}
	return isUsed, nil
}

func (r *AuthRepo) GetUserRole(userID string) (string, error) {
	var role string
	query := `SELECT role FROM users WHERE id = ?`
	err := r.DB.QueryRow(query, userID).Scan(&role)
	return role, err
}

func (r *AuthRepo) RegisterUserWithInvite(user models.User, inviteCode string, avatar string) error {
	tx, err := r.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var createdBy string
	var isUsed bool
	err = tx.QueryRow(`SELECT created_by, is_used FROM invites WHERE code = ?`, inviteCode).Scan(&createdBy, &isUsed)
	if err != nil {
		return errors.New("invite code not found")
	}
	if isUsed {
		return errors.New("invite code already used")
	}

	role := "user"
	if createdBy == "system" {
		role = "admin"
	}

	_, err = tx.Exec(`UPDATE invites SET is_used = TRUE WHERE code = ?`, inviteCode)
	if err != nil {
		return err
	}

	query := `INSERT INTO users (id, username, password_hash, public_key, encrypted_private_key, avatar, role) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err = tx.Exec(query, user.ID, user.Username, user.PasswordHash, user.PublicKey, user.EncryptedPrivateKey, avatar, role)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (r *AuthRepo) GetUserByUsername(username string) (models.User, error) {
	var u models.User
	query := `SELECT id, username, password_hash, public_key, encrypted_private_key, avatar FROM users WHERE username = ?`
	err := r.DB.QueryRow(query, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.PublicKey, &u.EncryptedPrivateKey, &u.Avatar)
	return u, err
}

func (r *AuthRepo) DeleteUser(userID string) (string, error) {
	tx, err := r.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var avatar sql.NullString
	err = tx.QueryRow(`SELECT avatar FROM users WHERE id = ?`, userID).Scan(&avatar)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("user not found")
		}
		return "", err
	}

	_, err = tx.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	if avatar.Valid {
		return avatar.String, nil
	}
	return "", nil
}

func (r *AuthRepo) BanUser(userID string, durationSeconds int64, reason string) error {
	var role string
	_ = r.DB.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role)
	if role == "admin" {
		return errors.New("cannot ban an admin account")
	}

	var expiresAt int64 = 0
	if durationSeconds > 0 {
		expiresAt = time.Now().Unix() + durationSeconds
	}

	query := `UPDATE users SET status = 'banned', ban_expires_at = ?, ban_reason = ? WHERE id = ?`
	_, err := r.DB.Exec(query, expiresAt, reason, userID)
	return err
}

func (r *AuthRepo) UnbanUser(userID string) error {
	query := `UPDATE users SET status = 'active', ban_expires_at = 0, ban_reason = NULL WHERE id = ?`
	_, err := r.DB.Exec(query, userID)
	return err
}

func (r *AuthRepo) CheckUserBanStatus(userID string) (bool, string, error) {
	var status string
	var banExpiresAt int64
	var banReason sql.NullString

	query := `SELECT status, ban_expires_at, ban_reason FROM users WHERE id = ?`
	err := r.DB.QueryRow(query, userID).Scan(&status, &banExpiresAt, &banReason)
	if err != nil {
		return false, "", err
	}

	if status != "banned" {
		return false, "", nil
	}

	if banExpiresAt > 0 && time.Now().Unix() > banExpiresAt {
		_ = r.UnbanUser(userID)
		return false, "", nil
	}

	reason := "No reason provided"
	if banReason.Valid {
		reason = banReason.String
	}

	return true, reason, nil
}

func (r *AuthRepo) SearchUser(username string) (models.User, error) {
	var u models.User
	query := `
        SELECT id, username, public_key, avatar FROM users 
        WHERE username = ? 
        AND username NOT LIKE '\_%' 
        AND username NOT LIKE '%_bot'
    `
	err := r.DB.QueryRow(query, username).Scan(&u.ID, &u.Username, &u.PublicKey, &u.Avatar)
	return u, err
}

func (r *AuthRepo) GetPasswordHash(userID string) (string, error) {
	var passwordHash string
	query := `SELECT password_hash FROM users WHERE id = ?`
	err := r.DB.QueryRow(query, userID).Scan(&passwordHash)
	return passwordHash, err
}

func (r *AuthRepo) UpdatePassword(userID, newHash, newEncPrivKey string) error {
	query := `UPDATE users SET password_hash = ?, encrypted_private_key = ? WHERE id = ?`
	_, err := r.DB.Exec(query, newHash, newEncPrivKey, userID)
	return err
}
