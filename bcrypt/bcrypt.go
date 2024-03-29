package bcrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"

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
	hashSize           = 60
)

const (
	// MinCost is the minimum allowable cost as passed in to GenerateFromPassword
	MinCost uint = 4
	// MaxCost is the maximum allowable cost as passed in to GenerateFromPassword
	MaxCost uint = 31
	// DefaultCost is the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
	DefaultCost uint = 10
)

const encodeStd = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var stdEncoding = base64.NewEncoding(encodeStd)

// "OrpheanBeholderScryDoubt"という文字列のバイト配列
// https://play.golang.org/p/AtRJ6WdnC4c
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}

var errMismatchedHashAndPassword = errors.New("crypto/bcrypt: hashedPassword is not the hash of the given password")
var errHashTooShort = errors.New("crypto/bcrypt: hashedSecret too short to be a bcrypted password")
var errInvalidHash = errors.New("crypto/bcrypt: invalid hashedPassword")
var errInvalidVersion = errors.New("crypto/bcrypt: invalid version")
var errPasswordIsEmpty = errors.New("password is empty")
var errPasswordTooLong = errors.New("password is too long")

type errInvalidCost uint

func (e errInvalidCost) Error() string {
	return fmt.Sprintf("bcrypt: cost %d is out of range. allowed %d to %d", e, MinCost, MaxCost)
}

type hashed struct {
	majorVersion byte
	minorVersion byte
	cost         uint
	salt         []byte
	passwordHash []byte
}

// GenerateHash generates hash value from raw password.
func GenerateHash(password string, cost uint) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}

	if err := validateCost(cost); err != nil {
		return "", err
	}

	hashedBytes, err := generateHash([]byte(password), cost)
	return string(hashedBytes), err
}

func validatePassword(password string) error {
	if len(password) == 0 {
		return errPasswordIsEmpty
	}
	if len(password) > 72 {
		// エラーにする必要はない
		// bcryptは73文字以降を無視してしまう
		return errPasswordTooLong
	}

	return nil
}

func validateCost(cost uint) error {
	if cost < MinCost || cost > MaxCost {
		// costが0~31なのは、
		// int32の最大値が2147483647で、
		// 0~(2**31-1=2147483647) 回試行する為
		// オーバーフローしてしまうから。
		return errInvalidCost(cost)
	}

	return nil
}

func generateHash(password []byte, cost uint) ([]byte, error) {
	// ソルトの生成
	salt, err := makeSalt()
	if err != nil {
		return nil, err
	}

	// パスワードをハッシュ化する
	passwordHash, err := bcrypt(password, cost, salt)
	if err != nil {
		return nil, err
	}

	p := hashed{
		majorVersion: majorVersion, // major versionの付与
		minorVersion: minorVersion, // minor versionの付与(a/b)
		cost:         cost,
		salt:         salt,
		passwordHash: passwordHash,
	}

	// ハッシュ値の生成
	return p.Hash(), nil
}

func makeSalt() ([]byte, error) {
	// maxSaltSize分配列を確保する
	unencodedSalt := make([]byte, maxSaltSize)
	// unencodedSaltを全てランダムな文字で埋める
	if _, err := io.ReadFull(rand.Reader, unencodedSalt); err != nil {
		return nil, err
	}
	// unencodedSaltをbase64Encodeする
	return base64Encode(unencodedSalt), nil
}

func base64Encode(src []byte) []byte {
	// See: https://play.golang.org/p/5D5McYeNY-V

	// nバイト長の入力バッファをエンコードしたときのバイト数を返します。
	n := stdEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	// encを使用してsrcをエンコードしdstへEncodedLen(len(src))バイト書き込みを行います。
	stdEncoding.Encode(dst, src)
	// パディングされている分は省く
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

func base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	// パディングを除去しているので元に戻す
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	// シンプルにエンコードと逆のことをやっている
	dst := make([]byte, stdEncoding.DecodedLen(len(src)))
	n, err := stdEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func bcrypt(password []byte, cost uint, salt []byte) ([]byte, error) {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
	if err != nil {
		return nil, err
	}

	// この数字の意味は？
	// iは3loop, jは64loopで計192loopする
	// See: https://ja.wikipedia.org/wiki/Bcrypt
	// bcryptのアルゴリズムは`OrpheanBeholderScryDoubt`を
	// Blowfishを用いて64回暗号化した文字列を作成する。
	// bcryptでは通常のBlowfishの鍵セットアップ関数をコストが高価な（expensive key setup）
	// EksBlowfishSetup関数に置き換えている:

	// "OrpheanBeholderScryDoubt"という文字列を使って64回暗号化する
	// c.Encryptは8byteずつ処理されるので、8文字ごとに64回暗号化している
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			// 内部でひたすらシフト演算を繰り返し、引数を上書いている
			// Decryptは同じ値の逆シフト演算をするので、元に戻るという仕組み
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}

	// Bug compatibility with C bcrypt implementations. We only encode 23 of
	// the 24 bytes encrypted.
	hsh := base64Encode(cipherData[:maxCryptedHashSize])
	return hsh, nil
}

func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
	// saltをデコードする
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
	// <<はシフト演算
	// e.g.
	// 10 >> 1 => 10を2進数で表現すると1010で、それを右に1bitシフトすると101なので5
	// 10 << 2 => 1010を左に2bitシフトすると、101000なので40
	// この場合は1を左にcost分シフトする。
	// roundsが符号なし(uint)か符号あり(int)かによってシフト後の数値は変わる
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		// パスワードを暗号化する
		blowfish.ExpandKey(ckey, c)
		// ソルトを暗号化する
		blowfish.ExpandKey(csalt, c)
	}

	return c, nil
}

func (p *hashed) Hash() []byte {
	// 60文字
	arr := make([]byte, hashSize)
	// 1文字目は必ず`$`
	arr[0] = '$'
	// major version 2
	arr[1] = p.majorVersion
	n := 2
	if p.minorVersion != 0 {
		// minor version `a`
		arr[2] = p.minorVersion
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
	copy(arr[n:], p.passwordHash)
	n += encodedHashSize
	// 結果を返却
	return arr[:n]
}

// IsCorrectPassword compares hashed value and raw password.
func IsCorrectPassword(hashedPassword, password string) error {
	hashedBytes := []byte(hashedPassword)

	if len(hashedBytes) < hashSize {
		return errHashTooShort
	}

	// ハッシュ値からversionを取得
	versionBytes, err := version(hashedBytes)
	if err != nil {
		return err
	}

	// ハッシュ値からcostを取得
	costBytes, err := cost(hashedBytes)
	if err != nil {
		return err
	}

	var n int
	n++                    // $
	n += len(versionBytes) // e.g. 2a
	n++                    // $
	n += len(costBytes)    // e.g. 04
	n++

	salt := hashedBytes[n : n+encodedSaltSize+1]

	cost, err := strconv.Atoi(string(costBytes))
	if err != nil {
		return err
	}

	// 同じコストとソルトを用いてハッシュ化
	passwordHash, err := bcrypt([]byte(password), uint(cost), salt)
	if err != nil {
		return err
	}

	// パスワード部のみ比較
	if subtle.ConstantTimeCompare(hashedBytes[n+encodedSaltSize+1:], passwordHash) == 1 {
		return nil
	}

	return errMismatchedHashAndPassword
}

func version(hashedBytes []byte) ([]byte, error) {
	if hashedBytes[0] != '$' {
		return nil, errInvalidHash
	}
	if hashedBytes[1] > majorVersion {
		return nil, errInvalidVersion
	}
	if hashedBytes[2] != '$' {
		return hashedBytes[1:3], nil
	}

	return hashedBytes[1:2], nil
}

func cost(hashedBytes []byte) ([]byte, error) {
	if hashedBytes[0] != '$' {
		return nil, errInvalidHash
	}

	if hashedBytes[2] == '$' {
		// e.g. $2$04...
		return hashedBytes[3:5], nil
	}

	// e.g. $2a$04...
	return hashedBytes[4:6], nil
}
