package cryptography

import (
	"errors"
	"reflect"
	"testing"
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
		})
	}
}
