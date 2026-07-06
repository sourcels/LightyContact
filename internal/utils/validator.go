package utils

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must contain minimum 8 characters")
	}
	var hasUpper, hasSpecial bool
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		}
		if unicode.IsPunct(char) || unicode.IsSymbol(char) {
			hasSpecial = true
		}
	}
	if !hasUpper {
		return errors.New("password must contain minimum 1 capital character")
	}
	if !hasSpecial {
		return errors.New("password must contain minimum 1 special character")
	}
	return nil
}

func ValidateUsername(name string) error {
	if name == "_root" || name == "system_bot" {
		return errors.New("system names are reserved")
	}
	matched, _ := regexp.MatchString(`^[a-z0-9_]+$`, name)
	if !matched {
		return errors.New("username must contain only small characters, numbers and underscore")
	}
	if strings.HasPrefix(name, "_") {
		return errors.New("username cannot start with underscore")
	}
	if strings.HasSuffix(name, "_bot") {
		return errors.New("using _bot postfix is not allowed")
	}
	return nil
}
