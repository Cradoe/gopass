package gopass

import (
	"strconv"
	"testing"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

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

			if !test.valid && valid {
				t.Errorf("expected failure but got success for password: %s", test.password)
			}

			if test.valid && !valid {
				t.Errorf("expected success but got failure for password: %s, errors: %v", test.password, errs)
			}
		})
	}
}

func TestGenerateOTP(t *testing.T) {
	t.Run("valid length", func(t *testing.T) {
		length := 9
		otp, err := GenerateOTP(length)
		if err != nil {
			t.Fatalf("GenerateOTP() error = %v", err)
		}

		if _, err = strconv.Atoi(otp); err != nil {
			t.Fatalf("%q is not convertible to number.\n", otp)
		}

	})

	t.Run("invalid length", func(t *testing.T) {
		length := 3
		_, err := GenerateOTP(length)
		if err == nil {
			t.Fatalf("GenerateOTP() error = %v, want true", err)
		}

	})
}

func TestHashWithBcrypt(t *testing.T) {
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
			hashedPassword, err := HashWithBcrypt(tt.password, tt.cost)
			if err != nil {
				t.Fatalf("HashWithBcrypt() error = %v, wantErr = nil", err)
			}

			if hashedPassword == "" {
				t.Fatalf("HashWithBcrypt() returned an empty string")
			}

			if match, _ := CompareBcryptPasswordAndHash(tt.password, hashedPassword); !match {
				t.Fatalf("CompareBcryptPasswordAndHash() = false, want true")
			}
		})
	}
}

func TestCompareBcryptPasswordAndHash(t *testing.T) {
	t.Run("valid match", func(t *testing.T) {
		password := "password123"
		hashedPassword, err := HashWithBcrypt(password, bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("HashWithBcrypt() error = %v", err)
		}

		match, err := CompareBcryptPasswordAndHash(password, hashedPassword)
		if err != nil {
			t.Fatalf("CompareBcryptPasswordAndHash() error = %v", err)
		}
		if !match {
			t.Fatalf("CompareBcryptPasswordAndHash() = false, want true")
		}
	})

	t.Run("invalid match", func(t *testing.T) {
		password := "password123"
		hashedPassword, err := HashWithBcrypt("otherpassword", bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("HashWithBcrypt() error = %v", err)
		}

		match, err := CompareBcryptPasswordAndHash(password, hashedPassword)
		if err != nil {
			t.Fatalf("CompareBcryptPasswordAndHash() error = %v", err)
		}
		if match {
			t.Fatalf("CompareBcryptPasswordAndHash() = true, want false")
		}
	})
}

func TestGeneratePasswordWithDefault(t *testing.T) {
	password, err := GeneratePassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(password) != 12 {
		t.Errorf("expected length 12, got %d", len(password))
	}
}

func TestGeneratePasswordWithCustomLength(t *testing.T) {
	options := GeneratePasswordOptions{Length: 20, IncludeUpper: true, IncludeLower: true, IncludeNumbers: true, IncludeSymbols: true}
	password, err := GeneratePassword(options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(password) != 20 {
		t.Errorf("expected length 20, got %d", len(password))
	}
}

func TestGeneratePasswordWithCharacterTypes(t *testing.T) {
	options := GeneratePasswordOptions{Length: 10, IncludeUpper: true, IncludeLower: false, IncludeNumbers: false, IncludeSymbols: false}
	password, err := GeneratePassword(options)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	containsUpper := false
	for _, ch := range password {
		if unicode.IsUpper(ch) {
			containsUpper = true
		}
	}
	if !containsUpper {
		t.Errorf("password does not contain uppercase letter")
	}
}

func TestGeneratePasswordShuffling(t *testing.T) {
	options := GeneratePasswordOptions{Length: 15, IncludeUpper: true, IncludeLower: true, IncludeNumbers: true, IncludeSymbols: true}
	password1, _ := GeneratePassword(options)
	password2, _ := GeneratePassword(options)
	if password1 == password2 {
		t.Errorf("passwords should be different: %s == %s", password1, password2)
	}
}
