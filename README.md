# Gopass

`gopass` is a Go package that provides utilities for password security, validation, hashing, comparison, and OTP (One-Time Password) generation.

## Features

- **Commonly used:** Checks if password is part of the 10k most commonly used passwords.
- **Password Validation:** Ensures password is strong by checking the length, character requirements, and is not part of the commonly used passwords.
- **Secure Hashing:** Hash passwords securely using bcrypt hashing algorithm.
- **Password Comparison:** Compares bcrypt hashed passwords with plaintext.
- **OTP Generation:** Create numeric one-time passwords of configurable lengths.

## Installation

To install `gopass`, run:

```sh
 go get github.com/cradoe/gopass
```

## Usage

### Password Validation

Ensure password is strong and meets security requirements:

```go
package main

import (
	"fmt"
	"github.com/cradoe/gopass"
)

func main() {
	valid, errors := gopass.Validate("SecurePass123!")
	if valid {
		fmt.Println("Password is strong!")
	} else {
		fmt.Println("Password issues:")
		for _, err := range errors {
			fmt.Println("-", err)
		}
	}
}
```

### Is common

Check if the given password is part of the 10k most used passwords:

```go
package main

import (
	"fmt"
	"github.com/cradoe/gopass"
)

func main() {
	common := gopass.IsCommon("football")
	if common {
		fmt.Println("Password is too common")
		return
	}
}
```

### Password Hashing and Comparison

Securely hash and verify passwords using Bcrypt hash algorithm:

```go
package main

import (
	"fmt"
	"github.com/cradoe/gopass"
)

func main() {
	password := "SecurePass123!"
	hashedPassword, err := gopass.Hash(password)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return
	}

	fmt.Println("Hashed Password:", hashedPassword)

	match, err := gopass.ComparePasswordAndHash(password, hashedPassword)
	if err != nil {
		fmt.Println("Error comparing password:", err)
		return
	}

	if match {
		fmt.Println("Password matches!")
	} else {
		fmt.Println("Invalid password!")
	}
}
```

### Generating One-Time Passwords (OTPs)

Generate a numeric OTP:

```go
package main

import (
	"fmt"
	"github.com/cradoe/gopass"
)

func main() {
	otp, err := gopass.GenerateOTP(6) // using 6 as the length of the OTP
	if err != nil {
		fmt.Println("Error generating OTP:", err)
		return
	}
	fmt.Println("Generated OTP:", otp)
}
```

## Errors and Limitations

`gopass` enforces security by rejecting:

- Passwords shorter than 8 characters or longer than 72 characters.
- Passwords missing uppercase, lowercase, numeric, or special characters.
- Commonly used passwords (from a predefined list).
- OTP lengths shorter than 4 digits.

## Roadmap

- Support for additional hashing algorithms (e.g., Argon2, PBKDF2).
- Configurable password policies.

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests on GitHub.
