package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret []byte

func Init(secret string) error {
	if secret == "" {
		return errors.New("Critical Error: JWT_SECRET not assigned")
	}
	jwtSecret = []byte(secret)
	return nil
}

func GenerateToken(userID string) (string, error) {
	if jwtSecret == nil {
		return "", errors.New("JWT secret is not initialized")
	}

	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (string, error) {
	if jwtSecret == nil {
		return "", errors.New("JWT secret is not initialized")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signature algorithm")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("error read token data")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("token is not containing user_id")
	}

	return userID, nil
}
