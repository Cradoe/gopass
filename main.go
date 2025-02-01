package gopass

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func Hash(plaintextPassword string, cost int) (string, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), cost)
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

func Common[T comparable](value T) bool {
	// Check if the type T is a string before proceeding with comparisons
	if strValue, ok := any(value).(string); ok {
		for _, commonPassword := range CommonPasswords {
			if strValue == commonPassword {
				return true
			}
		}
	}
	return false
}
