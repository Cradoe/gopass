package gopass

import (
	"errors"

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
