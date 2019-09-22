package bcrypt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func Test_BCrypt_GenerateFromPassword(t *testing.T) {
	tests := []struct {
		name string
		in   struct {
			password string
			cost     uint
		}
		wantErr error
	}{
		{
			name: "regular case",
			in: struct {
				password string
				cost     uint
			}{
				"11111111",
				4,
			},
			wantErr: nil,
		},
		{
			name: "regular case",
			in: struct {
				password string
				cost     uint
			}{
				"anif8nb4FFVF9sxF",
				4,
			},
			wantErr: nil,
		},
		{
			name: "password is empty",
			in: struct {
				password string
				cost     uint
			}{
				"",
				4,
			},
			wantErr: errPasswordIsEmpty,
		},
		{
			name: "password too long",
			in: struct {
				password string
				cost     uint
			}{
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijk",
				4,
			},
			wantErr: errPasswordTooLong,
		},
		{
			name: "invalid cost",
			in: struct {
				password string
				cost     uint
			}{
				"abcdefgh",
				32,
			},
			wantErr: errInvalidCost(32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateHash(tt.in.password, tt.in.cost)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("GenerateHash(%s, %d)=_, %#v; want %#v", tt.in.password, tt.in.cost, err, tt.wantErr)
			}
			if err != nil {
				return
			}

			strs := strings.Split(got, "$")
			// str[0] is empty
			if strs[1][0] != majorVersion {
				t.Errorf("GenerateHash(%s, %d) incorrect major version: %b; want %b", tt.in.password, tt.in.cost, strs[1][0], majorVersion)
			}
			if strs[1][1] != minorVersion {
				t.Errorf("GenerateHash(%s, %d) incorrect minor version: %b; want %b", tt.in.password, tt.in.cost, strs[1][1], minorVersion)
			}
			if cost := fmt.Sprintf("%02d", tt.in.cost); strs[2] != cost {
				t.Errorf("GenerateHash(%s, %d) incorrect cost: %s; want %s", tt.in.password, tt.in.cost, strs[1], cost)
			}
		})
	}
}

func Test_BCrypt_IsCorrectPassword(t *testing.T) {
	tests := []struct {
		name string
		in   struct {
			passwordHash string
			password     string
		}
		wantErr error
	}{
		{
			name: "regular case",
			in: struct {
				passwordHash string
				password     string
			}{
				"$2a$04$DtzdGW/0HF6SEE5yYsAFee7C/xkgRD2if0rAsu3/.gmj8NxWZAbPq",
				"11111111",
			},
			wantErr: nil,
		},
		{
			name: "regular case",
			in: struct {
				passwordHash string
				password     string
			}{
				"$2a$11$.uxjK2m8ZJHvj5sSSOt7.u8cFC5IDo7N1fRg2qbETdZmlCn2OFvui",
				"ce249uf21FCerv8u4WEFVDc8uc782fcwEC",
			},
			wantErr: nil,
		},
		{
			name: "password hash too short",
			in: struct {
				passwordHash string
				password     string
			}{
				"$2a$11$.uxjK2m8ZJHvj5sSSOt7.u8cFC5IDo7N1fRg2qbETdZmlCn2OFv",
				"",
			},
			wantErr: errHashTooShort,
		},
		{
			name: "password is empty",
			in: struct {
				passwordHash string
				password     string
			}{
				"$2a$11$.uxjK2m8ZJHvj5sSSOt7.u8cFC5IDo7N1fRg2qbETdZmlCn2OFvui",
				"ce249uf21FCerv8u4WEFVDc8uc782fcwEC",
			},
			wantErr: errPasswordIsEmpty,
		},
		{
			name: "mismatched password hash and password",
			in: struct {
				passwordHash string
				password     string
			}{
				"$2a$11$.uxjK2m8ZJHvj5sSSOt7.u8cFC5IDo7N1fRg2qbETdZmlCn2OFvui",
				"11111111",
			},
			wantErr: errMismatchedHashAndPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsCorrectPassword(tt.in.passwordHash, tt.in.password)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("IsCorrectPassword(%s, %s)=_, %#v; want %#v", tt.in.passwordHash, tt.in.password, err, tt.wantErr)
			}
		})
	}
}
