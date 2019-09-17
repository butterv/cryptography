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
				0,
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
				0,
			},
			wantErr: ErrPasswordIsEmpty,
		},
		{
			name: "password too long",
			in: struct {
				password string
				cost     uint
			}{
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijk",
				0,
			},
			wantErr: ErrPasswordTooLong,
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
			wantErr: ErrInvalidCost(32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateFromPassword(tt.in.password, tt.in.cost)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Fatalf("GenerateFromPassword(%s, %d)=_, %#v; want %#v", tt.in.password, tt.in.cost, err, tt.wantErr)
			}
			if err != nil {
				return
			}

			strs := strings.Split(got, "$")
			// str[0] is empty
			if strs[1][0] != majorVersion {
				t.Errorf("GenerateFromPassword(%s, %d) incorrect major version: %b; want %b", tt.in.password, tt.in.cost, strs[1][0], majorVersion)
			}
			if strs[1][1] != minorVersion {
				t.Errorf("GenerateFromPassword(%s, %d) incorrect minor version: %b; want %b", tt.in.password, tt.in.cost, strs[1][1], minorVersion)
			}
			if cost := fmt.Sprintf("%02d", tt.in.cost); strs[2] != cost {
				t.Errorf("GenerateFromPassword(%s, %d) incorrect cost: %s; want %s", tt.in.password, tt.in.cost, strs[1], cost)
			}
		})
	}
}
