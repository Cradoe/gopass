// Package gopass provides utilities for password generation, validation, hashing, comparison, and OTP generation.

// This package helps developers enforce password security policies, generate secure passwords, one-time passwords (OTPs) for authentication systems.
// It also hash passwords securely, currently supports bcrypt,
// other algorithms will be provided in the future.

// Features:
// - Validate password strength based on length, character requirements, and common password checks.
// - Securely hash passwords using bcrypt with customizable cost factors.
// - Compare plaintext passwords with hashed values to verify authentication.
// - Generate random password that is secure, allows customizable options.
// - Generate numeric OTPs of configurable lengths.

// "Hash* functions" denotes all functions that is, or starts with "Hash" and
// are used for the purpose of hashing.
// Example of this is HashWithBcrypt

package gopass

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrEmptyPassword is returned by Hash* if the provided
	// plaintextPassword is ""
	ErrEmptyPassword = errors.New("password cannot be empty")

	// ErrPasswordTooShort is returned by Validate if the provided
	// password is less than 8 characters
	ErrPasswordTooShort = errors.New("password must be at least 8 characters long")

	// ErrPasswordTooLong is returned by Validate and Hash* functions if the provided
	// password is more than 72 characters
	ErrPasswordTooLong = errors.New("password length exceeds 72 characters")

	// ErrPasswordShouldHaveUppercase is returned by Validate if the provided
	// password does not have an uppercase letter
	ErrPasswordShouldHaveUppercase = errors.New("password must contain at least one uppercase letter")

	// ErrPasswordShouldHaveUppercase is returned by Validate if the provided
	// password does not have an uppercase letter
	ErrPasswordShouldHaveLowercase = errors.New("password must contain at least one lowercase letter")

	// ErrPasswordShouldHaveDigit is returned by Validate if the provided
	// password does not have a digit letter
	ErrPasswordShouldHaveDigit = errors.New("password must contain at least one number")

	// ErrPasswordShouldHaveSpecialChar is returned by Validate if the provided
	// password does not have a special character
	ErrPasswordShouldHaveSpecialChar = errors.New("password must contain at least one special character")

	// ErrPasswordTooCommon is returned by Validate if the provided
	// password is passed to IsCommon, which then returns true
	ErrPasswordTooCommon = errors.New("password is too common, please choose a stronger one")

	// ErrInvalidOTPLength is returned by GenerateOTP if the provided
	// length is less than 4
	ErrInvalidOTPLength = errors.New("OTP length must be at least 4 digits")
)

// IsCommon checks if the provided password is present in a list of
// 10k commonly used passwords
// see https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
func IsCommon(value string) bool {
	for _, commonPassword := range CommonPasswords {
		if value == commonPassword {
			return true
		}
	}
	return false
}

// Validate checks the strength of a password based on the following criteria:
// - Minimum length of 8 characters
// - Maximum length of 72 characters (bcrypt limitation)
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one number
// - At least one special character
// - Is not common password
//
// It returns a boolean indicating validity and a slice of errors describing any issues.
func Validate(value string) (bool, []error) {
	var errors []error
	if len(value) < 8 {
		errors = append(errors, ErrPasswordTooShort)
	}
	if len(value) > 72 {
		errors = append(errors, ErrPasswordTooLong)
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
		errors = append(errors, ErrPasswordShouldHaveUppercase)
	}
	if !hasLower {
		errors = append(errors, ErrPasswordShouldHaveLowercase)
	}
	if !hasDigit {
		errors = append(errors, ErrPasswordShouldHaveDigit)
	}
	if !hasSpecial {
		errors = append(errors, ErrPasswordShouldHaveSpecialChar)
	}
	if IsCommon(value) {
		errors = append(errors, ErrPasswordTooCommon)
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}

// GenerateOTP generates a one-time password (OTP) of the specified length.
// The OTP consists only of numeric digits (0-9).
//
// Returns the generated OTP as a string or an error if the length is invalid.
func GenerateOTP(length int) (string, error) {
	if length < 4 {
		return "", ErrInvalidOTPLength
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

// Hash securely hashes a plaintext password,
// It uses Bcrypt by default
func Hash(plaintextPassword string, cost ...int) (string, error) {
	return HashWithBcrypt(plaintextPassword, cost...)
}

// ComparePasswordAndHash verifies a plaintext password against a hashed password.
// It uses Bcrypt as default
// Returns true if they match, false otherwise.
func ComparePasswordAndHash(plaintextPassword, hashedPassword string) (match bool, err error) {
	return CompareBcryptPasswordAndHash(plaintextPassword, hashedPassword)
}

// HashWithBcrypt hashes a password using bcrypt
// it ensures the password is not empty and not more than 72 characters.
// There is an optional parameter for specifying the cost
func HashWithBcrypt(plaintextPassword string, cost ...int) (string, error) {
	if plaintextPassword == "" {
		return "", ErrEmptyPassword
	}
	if len(plaintextPassword) > 72 {
		return "", ErrPasswordTooLong
	}

	bcryptCost := bcrypt.DefaultCost
	if len(cost) > 0 && cost[0] > 0 {
		bcryptCost = cost[0]
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), bcryptCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

// BcryptCost gets the bcrypt cost factor from a hashed password.
// Returns the cost factor or an error if the extraction fails.
func BcryptCost(hashedPassword string) (cost int, err error) {
	cost, err = bcrypt.Cost([]byte(hashedPassword))
	if err != nil {
		return 0, err
	}
	return cost, nil
}

// CompareBcryptPasswordAndHash compares a plaintext password with a bcrypt hash.
// Returns true if they match, false if they don't, and an error if something goes wrong.
func CompareBcryptPasswordAndHash(plaintextPassword, hashedPassword string) (match bool, err error) {
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plaintextPassword))
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

// Character sets for password generation
const (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberChars = "0123456789"
	symbolChars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/~"
)

type GeneratePasswordOptions struct {
	Length         int
	IncludeUpper   bool
	IncludeLower   bool
	IncludeNumbers bool
	IncludeSymbols bool
}

// GeneratePassword randomly generates a secure password,
// It has options for customizing it's behavior,  option is used when custom isn't given
//
// Returns the generated password as a string or an error if there's any
func GeneratePassword(params ...GeneratePasswordOptions) (string, error) {
	options := GeneratePasswordOptions{
		Length:         12,
		IncludeUpper:   true,
		IncludeLower:   true,
		IncludeNumbers: true,
		IncludeSymbols: true,
	}

	// check and use custom options if params is given
	if len(params) > 0 {
		options = params[0]
	}

	// Validate minimum length requirement
	if options.Length < 4 {
		return "", errors.New("password length must be at least 4 characters")
	}

	// Build character pool
	charPool := ""
	if options.IncludeLower {
		charPool += lowerChars
	}
	if options.IncludeUpper {
		charPool += upperChars
	}
	if options.IncludeNumbers {
		charPool += numberChars
	}
	if options.IncludeSymbols {
		charPool += symbolChars
	}

	if len(charPool) == 0 {
		return "", errors.New("at least one character type must be selected")
	}

	// Let's ensure that at the password have at least one charcter from the selected character pool
	var password strings.Builder
	if options.IncludeLower {
		password.WriteByte(lowerChars[randInt(len(lowerChars))])
	}
	if options.IncludeUpper {
		password.WriteByte(upperChars[randInt(len(upperChars))])
	}
	if options.IncludeNumbers {
		password.WriteByte(numberChars[randInt(len(numberChars))])
	}
	if options.IncludeSymbols {
		password.WriteByte(symbolChars[randInt(len(symbolChars))])
	}

	// Fill the rest of the password
	for password.Len() < options.Length {
		password.WriteByte(charPool[randInt(len(charPool))])
	}

	// We need to suffle the string to avoid predictable pattern
	result := shuffleString(password.String())

	return result, nil
}

// randInt generates a random number that is cryptographically secure
func randInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

// shuffleString shuffles characters randomly
func shuffleString(input string) string {
	runes := []rune(input)
	for i := range runes {
		j := randInt(len(runes))
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
