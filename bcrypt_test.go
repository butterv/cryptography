package cryptography

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func Test_BCrypt_HashPassword(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{
			name:    "regular case success hash",
			in:      "uh4r5CVsd9TXfmPs",
			wantErr: nil,
		},
		{
			name:    "password is empty",
			in:      "",
			wantErr: errors.New("password is empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCrypt()
			got, err := b.HashPassword(tt.in)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("HashPassword(%s)=_, %#v; want %#v", tt.in, err, tt.wantErr)
			}

			isCorrect, _ := b.IsCorrectPassword(got, tt.in)
			if !isCorrect && tt.wantErr == nil {
				t.Errorf("IsCorrectPassword(%s, %s)=false, _; want true", got, tt.in)
			}

			cost, _ := bcrypt.Cost([]byte(got))
			if cost != bcrypt.DefaultCost && tt.wantErr == nil {
				t.Errorf("Cost([]byte(%s)=false, _; want true", got)
			}
		})
	}
}

func Test_BCrypt_IsCorrectPassword(t *testing.T) {
	tests := []struct {
		name string
		in   struct {
			hashedPassword string
			password       string
		}
		want    bool
		wantErr error
	}{
		{
			name: "regular case is correct",
			in: struct {
				hashedPassword string
				password       string
			}{
				"$2a$10$QKlsqjrE8fjsK9yuVAFzreXt.N3WfoGM1yKX5HgFwgAUcPd06MouK",
				"uh4r5CVsd9TXfmPs",
			},
			want:    true,
			wantErr: nil,
		},
		{
			name: "regular case is correct(password 76 chars)",
			in: struct {
				hashedPassword string
				password       string
			}{
				"$2a$10$6bi1p5YxjouGtXIef4eFveWHGDj1li92fA7dXsOA9vwaQGlHZaYh6",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			want:    true,
			wantErr: nil,
		},
		{
			name: "hashed password too short",
			in: struct {
				hashedPassword string
				password       string
			}{
				"hashedPassword",
				"password",
			},
			want:    false,
			wantErr: bcrypt.ErrHashTooShort,
		},
		{
			name: "mismatched hash and password",
			in: struct {
				hashedPassword string
				password       string
			}{
				"$2a$10$QKlsqjrE8fjsK9yuVAFzreXt.N3WfoGM1yKX5HgFwgAUcPd06MouK",
				"uh4r5CVsd9TXfmPa",
			},
			want:    false,
			wantErr: bcrypt.ErrMismatchedHashAndPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCrypt()
			got, err := b.IsCorrectPassword(tt.in.hashedPassword, tt.in.password)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("IsCorrectPassword(%s, %s)=_, %#v; want %#v", tt.in.hashedPassword, tt.in.password, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IsCorrectPassword(%s, %s)=%v, _; want %v", tt.in.hashedPassword, tt.in.password, got, tt.want)
			}
		})
	}
}
