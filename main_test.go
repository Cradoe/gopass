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
			result := IsCommon(tt.password)
			if result != tt.expected {
				t.Fatalf("Common() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		password string
		valid    bool
	}{
		{"Short1!", false},
		{"alllowercase1!", false},
		{"ALLUPPERCASE1!", false},
		{"NoNumbers!", false},
		{"NoSpecial123", false},
		{"ValidPass1!", true},
		{"WayTooLongPassword1234567890!WayTooLongPassword1234567890!WayTooLongPassword123", false},
		{"password", false},
	}

	for _, test := range tests {
		t.Run(test.password, func(t *testing.T) {
			valid, errs := Validate(test.password)

			// Check that invalid passwords return an error
			if !test.valid && valid {
				t.Errorf("expected failure but got success for password: %s", test.password)
			}

			// Check that valid passwords return no errors
			if test.valid && !valid {
				t.Errorf("expected success but got failure for password: %s, errors: %v", test.password, errs)
			}
		})
	}
}
