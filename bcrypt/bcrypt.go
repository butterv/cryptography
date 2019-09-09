package bcrypt

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

const saltPatten = "./A-Za-z0-9"
const encodeStd = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var stdEncoding = base64.NewEncoding(encodeStd)

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

func (*bcryptStruct) GenerateFromPassword(password []byte, cost int) ([]byte, error) {
	// 引数のパスワードの検証
	// 指定コストの検証(0~31)
	// 構造体`hashed`の初期化
	// major versionの付与(2)
	// マイナーバージョンの付与(a/b)
	// コストの付与
	// ソルトの生成
	// パスワード、コスト、ソルトでハッシュ化する
	// ハッシュ値の付与

	if len(password) == 0 {
		return nil, errors.New("password is empty")
	}
	// コストのチェック
	// TODO(istsh): 0~31の範囲に収まっているかの確認だけで十分かも
	if cost < MinCost {
		cost = DefaultCost
	}
	// 構造体`hashed`の初期化
	p := new(hashed)
	// major versionの付与(2)
	p.major = majorVersion
	// マイナーバージョンの付与(b)
	p.minor = minorVersion
	// コストのチェック
	err := checkCost(cost)
	if err != nil {
		return nil, err
	}
	// コストの付与
	p.cost = cost

	// ソルト
	// 指定サイズのバイト列
	unencodedSalt := make([]byte, maxSaltSize)
	// crypto/rand Reader, io.ReadFullでmaxSaltSize分乱数を生成する
	_, err = io.ReadFull(rand.Reader, unencodedSalt)
	if err != nil {
		return nil, err
	}
	// 生成してソルトをbase64エンコード
	p.salt = base64Encode(unencodedSalt)

	// 生パスワード、コスト、ソルトでハッシュ化する
	hash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}
	// ハッシュ値の付与
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
	// nバイト長の入力バッファをエンコードしたときのバイト数を返します。
	n := stdEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	// encを使用してsrcをエンコードしdstへEncodedLen(len(src))バイト書き込みを行います。
	stdEncoding.Encode(dst, src)
	// パディングされている分は省く
	for dst[n-1] == '=' {
		n--
	}

	// See: https://play.golang.org/p/5D5McYeNY-V

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

	dst := make([]byte, stdEncoding.DecodedLen(len(src)))
	n, err := stdEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func (p *hashed) Hash() []byte {
	// 60文字
	arr := make([]byte, 60)
	// 1文字目は必ず`$`
	arr[0] = '$'
	// major version 2
	arr[1] = p.major
	n := 2
	if p.minor != 0 {
		// minor version `a`
		arr[2] = p.minor
		n = 3
	}
	// バージョンの次の文字も必ず`$`
	arr[n] = '$'
	n++
	// `%02d`のフォーマットでコストを付与(2^nのnの数値が入る)
	copy(arr[n:], []byte(fmt.Sprintf("%02d", p.cost)))
	n += 2
	// コストの次の文字も必ず`$`
	arr[n] = '$'
	n++
	// ソルトを付与
	copy(arr[n:], p.salt)
	n += encodedSaltSize
	// パスワードのハッシュ値を付与
	copy(arr[n:], p.hash)
	n += encodedHashSize
	// 結果を返却
	return arr[:n]
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
