package gopass

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func Hash(plaintextPassword string, cost ...int) (string, error) {
	if len(cost) == 0 {
		cost = append(cost, bcrypt.DefaultCost)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), cost[0])
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func Matches(plaintextPassword, hashedPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plaintextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}

func IsCommon[T comparable](value T) bool {
	if strValue, ok := any(value).(string); ok {
		for _, commonPassword := range CommonPasswords {
			if strValue == commonPassword {
				return true
			}
		}
	}
	return false
}

func Validate[T comparable](value T) (bool, []string) {

	strValue, ok := any(value).(string)
	if !ok {
		return false, []string{"invalid password format"}
	}

	var errors []string
	if len(strValue) < 8 {
		errors = append(errors, "password must be at least 8 characters long")
	}
	if len(strValue) > 72 {
		errors = append(errors, "password must not be more than 72 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range strValue {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		errors = append(errors, "password must contain at least one uppercase letter")
	}
	if !hasLower {
		errors = append(errors, "password must contain at least one lowercase letter")
	}
	if !hasDigit {
		errors = append(errors, "password must contain at least one number")
	}
	if !hasSpecial {
		errors = append(errors, "password must contain at least one special character")
	}
	if IsCommon(strValue) {
		errors = append(errors, "password is too common, please choose a stronger one")
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}
