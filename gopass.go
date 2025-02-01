package gopass

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
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

func IsCommon(value string) bool {
	for _, commonPassword := range CommonPasswords {
		if value == commonPassword {
			return true
		}
	}
	return false
}

func Validate(value string) (bool, []string) {
	var errors []string
	if len(value) < 8 {
		errors = append(errors, "password must be at least 8 characters long")
	}
	if len(value) > 72 {
		errors = append(errors, "password must not be more than 72 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range value {
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
	if IsCommon(value) {
		errors = append(errors, "password is too common, please choose a stronger one")
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}

func GenerateOTP(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid length %d: must be greater than zero", length)
	}

	otp := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		otp[i] = byte('0') + byte(n.Int64())
	}

	return string(otp), nil
}
