package gopass

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHash(t *testing.T) {
	tests := []struct {
		password string
		cost     int
	}{
		{"password123", bcrypt.DefaultCost},
		{"shortpass", bcrypt.DefaultCost},
		{"anotherPassword", 14},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			hashedPassword, err := Hash(tt.password, tt.cost)
			if err != nil {
				t.Fatalf("Hash() error = %v, wantErr = nil", err)
			}

			// Check that the hash is not empty
			if hashedPassword == "" {
				t.Fatalf("Hash() returned an empty string")
			}

			// Check that the hash can be verified
			if match, _ := Matches(tt.password, hashedPassword); !match {
				t.Fatalf("Matches() = false, want true")
			}
		})
	}
}

func TestMatches(t *testing.T) {
	// Testing valid match
	t.Run("valid match", func(t *testing.T) {
		password := "password123"
		hashedPassword, err := Hash(password, bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}

		match, err := Matches(password, hashedPassword)
		if err != nil {
			t.Fatalf("Matches() error = %v", err)
		}
		if !match {
			t.Fatalf("Matches() = false, want true")
		}
	})

	// Testing invalid match
	t.Run("invalid match", func(t *testing.T) {
		password := "password123"
		hashedPassword, err := Hash("otherpassword", bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}

		match, err := Matches(password, hashedPassword)
		if err != nil {
			t.Fatalf("Matches() error = %v", err)
		}
		if match {
			t.Fatalf("Matches() = true, want false")
		}
	})
}

func TestCommon(t *testing.T) {
	tests := []struct {
		password string
		expected bool
	}{
		{"password", true},          // common password
		{"123456", true},            // common password
		{"ID)@*@)#NBHBJHWD", false}, // not in CommonPasswords
		{"!*ncKD_#%NJK+#C", false},  // not in CommonPasswords
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			result := Common(tt.password)
			if result != tt.expected {
				t.Fatalf("Common() = %v, want %v", result, tt.expected)
			}
		})
	}
}
