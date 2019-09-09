package bcrypt

import (
	"errors"
	"reflect"
	"testing"

	libBcrypy "golang.org/x/crypto/bcrypt"
)

func Test_BCrypt_Version(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{
			name:    "regular case version 2a",
			in:      "$2a$10$Q.Qos4YovNyRzlvHS8Y3LuhnRdyJgEX7IR27.eqLUIq41ktUyUC1y",
			want:    "2a",
			wantErr: nil,
		},
		{
			name:    "regular case version 2b",
			in:      "$2b$10$0DGBCMWhzppRvF2yVIIdoee9A1qAOq7bk39oQiZXXaQwvb.8o5.xO",
			want:    "2b",
			wantErr: nil,
		},
		{
			name:    "invalid hash",
			in:      "abcdefgh",
			wantErr: ErrInvalidHash,
		},
		{
			name:    "invalid version",
			in:      "$3b$10$0DGBCMWhzppRvF2yVIIdoee9A1qAOq7bk39oQiZXXaQwvb.8o5.xO",
			wantErr: ErrInvalidVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCrypt()
			in := []byte(tt.in)
			got, err := b.Version(in)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("Version(%v)=_, %#v; want %#v", in, err, tt.wantErr)
			}
			if string(got) != tt.want {
				t.Errorf("Version(%v)=%s, _; want %s", in, got, tt.want)
			}
		})
	}
}

func Test_BCrypt_Cost(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{
			name:    "regular case cost",
			in:      "$2a$10$Q.Qos4YovNyRzlvHS8Y3LuhnRdyJgEX7IR27.eqLUIq41ktUyUC1y",
			want:    10,
			wantErr: nil,
		},
		{
			name:    "regular case cost",
			in:      "$2b$04$0DGBCMWhzppRvF2yVIIdoee9A1qAOq7bk39oQiZXXaQwvb.8o5.xO",
			want:    4,
			wantErr: nil,
		},
		{
			name:    "hash too short",
			in:      "abcdefgh",
			wantErr: ErrHashTooShort,
		},
		{
			name:    "invalid hash",
			in:      "3b$10$0DGBCMWhzppRvF2yVIIdoee9A1qAOq7bk39oQiZXXaQwvb.8o5.xO",
			wantErr: ErrInvalidHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCrypt()
			in := []byte(tt.in)
			got, err := b.Cost(in)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("Cost(%v)=_, %#v; want %#v", in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Cost(%v)=%d, _; want %d", in, got, tt.want)
			}
		})
	}
}

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
			got, err := b.GenerateFromPassword([]byte(tt.in), 10)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("GenerateFromPassword(%s)=_, %#v; want %#v", tt.in, err, tt.wantErr)
			}

			isCorrect, _ := b.IsCorrectPassword(got, []byte(tt.in))
			if !isCorrect && tt.wantErr == nil {
				t.Errorf("GenerateFromPassword(%s, %s)=false, _; want true", got, tt.in)
			}

			cost, _ := libBcrypy.Cost([]byte(got))
			if cost != libBcrypy.DefaultCost && tt.wantErr == nil {
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
			wantErr: libBcrypy.ErrHashTooShort,
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
			wantErr: libBcrypy.ErrMismatchedHashAndPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := BCrypt()
			got, err := b.IsCorrectPassword([]byte(tt.in.hashedPassword), []byte(tt.in.password))
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("IsCorrectPassword(%s, %s)=_, %#v; want %#v", tt.in.hashedPassword, tt.in.password, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IsCorrectPassword(%s, %s)=%v, _; want %v", tt.in.hashedPassword, tt.in.password, got, tt.want)
			}
		})
	}
}
