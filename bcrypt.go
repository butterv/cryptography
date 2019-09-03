package cryptography

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type bcryptStruct struct{}

func BCrypt() *bcryptStruct {
	return &bcryptStruct{}
}

func (*bcryptStruct) HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (*bcryptStruct) IsCorrectPassword(hashedPassword, password string) (bool, error) {
	if hashedPassword == "" {
		return false, errors.New("hashedPassword is empty")
	}
	if password == "" {
		return false, errors.New("password is empty")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return false, err
	}
	return true, nil
}
