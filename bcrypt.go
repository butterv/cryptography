package cryptography

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"

	libBcrypt "golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blowfish"
)

const (
	majorVersion = '2'
	minorVersion = 'a'
	//minorVersion       = 'b'
	maxSaltSize        = 16
	maxCryptedHashSize = 23
	encodedSaltSize    = 22
	encodedHashSize    = 31
	minHashSize        = 59
)

const (
	MinCost     int = 4  // the minimum allowable cost as passed in to GenerateFromPassword
	MaxCost     int = 31 // the maximum allowable cost as passed in to GenerateFromPassword
	DefaultCost int = 10 // the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
)

const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet)

// magicCipherData is an IV for the 64 Blowfish encryption calls in
// bcrypt(). It's the string "OrpheanBeholderScryDoubt" in big-endian bytes.
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}

var ErrMismatchedHashAndPassword = errors.New("crypto/bcrypt: hashedPassword is not the hash of the given password")
var ErrHashTooShort = errors.New("crypto/bcrypt: hashedSecret too short to be a bcrypted password")
var ErrInvalidHash = errors.New("crypto/bcrypt: invalid hashedPassword")
var ErrInvalidVersion = errors.New("crypto/bcrypt: invalid version")

type hashed struct {
	hash  []byte
	salt  []byte
	cost  int // allowed range is MinCost to MaxCost
	major byte
	minor byte
}

type bcryptStruct struct{}

func BCrypt() *bcryptStruct {
	return &bcryptStruct{}
}

func (*bcryptStruct) Version(hashedBytes []byte) ([]byte, error) {
	if hashedBytes[0] != '$' {
		return nil, ErrInvalidHash
	}

	if hashedBytes[1] > majorVersion {
		return nil, ErrInvalidVersion
	}
	if hashedBytes[2] != '$' {
		return hashedBytes[1:3], nil
	}

	return hashedBytes[1:2], nil
}

func (*bcryptStruct) Cost(hashedBytes []byte) (int, error) {
	if len(hashedBytes) < minHashSize {
		return 0, ErrHashTooShort
	}

	if hashedBytes[0] != '$' {
		return 0, ErrInvalidHash
	}

	if hashedBytes[2] != '$' {
		cost, err := strconv.Atoi(string(hashedBytes[4:6]))
		if err != nil {
			return -1, err
		}
		return cost, nil
	}

	cost, err := strconv.Atoi(string(hashedBytes[5:7]))
	if err != nil {
		return -1, err
	}
	return cost, nil
}

func (*bcryptStruct) GenerateFromPassword(password []byte, cost int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password is empty")
	}

	if cost < MinCost {
		cost = DefaultCost
	}
	p := new(hashed)
	p.major = majorVersion
	p.minor = minorVersion

	err := checkCost(cost)
	if err != nil {
		return nil, err
	}
	p.cost = cost

	unencodedSalt := make([]byte, maxSaltSize)
	_, err = io.ReadFull(rand.Reader, unencodedSalt)
	if err != nil {
		return nil, err
	}
	p.salt = base64Encode(unencodedSalt)
	hash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}
	p.hash = hash
	return p.Hash(), err
}

func checkCost(cost int) error {
	if cost < MinCost || cost > MaxCost {
		return errors.New("invalid cost")
	}
	return nil
}

func base64Encode(src []byte) []byte {
	n := bcEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	bcEncoding.Encode(dst, src)
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

func bcrypt(password []byte, cost int, salt []byte) ([]byte, error) {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}

	// Bug compatibility with C bcrypt implementations. We only encode 23 of
	// the 24 bytes encrypted.
	hsh := base64Encode(cipherData[:maxCryptedHashSize])
	return hsh, nil
}

func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
	csalt, err := base64Decode(salt)
	if err != nil {
		return nil, err
	}

	// Bug compatibility with C bcrypt implementations. They use the trailing
	// NULL in the key string during expansion.
	// We copy the key to prevent changing the underlying array.
	ckey := append(key[:len(key):len(key)], 0)

	c, err := blowfish.NewSaltedCipher(ckey, csalt)
	if err != nil {
		return nil, err
	}

	var i, rounds uint64
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(csalt, c)
	}

	return c, nil
}

func base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	n, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func (p *hashed) Hash() []byte {
	arr := make([]byte, 60)
	arr[0] = '$'
	arr[1] = p.major
	n := 2
	if p.minor != 0 {
		arr[2] = p.minor
		n = 3
	}
	arr[n] = '$'
	n++
	copy(arr[n:], []byte(fmt.Sprintf("%02d", p.cost)))
	n += 2
	arr[n] = '$'
	n++
	copy(arr[n:], p.salt)
	n += encodedSaltSize
	copy(arr[n:], p.hash)
	n += encodedHashSize
	return arr[:n]
}

func (*bcryptStruct) IsCorrectPassword(hashedPassword, password []byte) (bool, error) {
	if len(hashedPassword) == 0 {
		return false, errors.New("hashedPassword is empty")
	}
	if len(password) == 0 {
		return false, errors.New("password is empty")
	}
	if err := libBcrypt.CompareHashAndPassword(hashedPassword, password); err != nil {
		return false, err
	}
	return true, nil
}
