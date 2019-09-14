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
	MinCost     uint = 0  // the minimum allowable cost as passed in to GenerateFromPassword
	MaxCost     uint = 31 // the maximum allowable cost as passed in to GenerateFromPassword
	DefaultCost uint = 10 // the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
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

type ErrInvalidCost uint

func (e ErrInvalidCost) Error() string {
	return fmt.Sprintf("bcrypt: cost %d is out of range. allowed %d to %d", e, MinCost, MaxCost)
}

func CompareHashAndPassword(hashedPassword, password string) error {
	hashedBytes := []byte(hashedPassword)

	if len(hashedBytes) < hashSize {
		return ErrHashTooShort
	}

	// パスワード部のハッシュ値が一致するかどうかを判定すればいいので、
	// バージョンは不要
	//version, err := version(hashedBytes)
	//if err != nil {
	//	return err
	//}

	cost, err := cost(hashedBytes)
	if err != nil {
		return err
	}

	// TODO: start num
	salt := hashedBytes[7 : 7+22]

	// TODO:
	// costは同じ値を使う必要があるが、2**cost分ストレッチングする必要があるか
	// パスワード部のハッシュ値を求めるのに同じ回数ストレッチングする必要がある？
	// このbcrypt関数の内部で何が行われているか、正確に理解する必要がある。
	hashed, err := bcrypt([]byte(password), cost, salt)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(hashedBytes, hashed) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

func version(hashedBytes []byte) ([]byte, error) {
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

func cost(hashedBytes []byte) (uint, error) {
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
		return uint(cost), nil
	}

	cost, err := strconv.Atoi(string(hashedBytes[5:7]))
	if err != nil {
		return -1, err
	}
	return uint(cost), nil
}

//func (*bcryptStruct) IsCorrectPassword(hashedPassword, password []byte) (bool, error) {
//	if len(hashedPassword) == 0 {
//		return false, errors.New("hashedPassword is empty")
//	}
//	if len(password) == 0 {
//		return false, errors.New("password is empty")
//	}
//	if err := libBcrypt.CompareHashAndPassword(hashedPassword, password); err != nil {
//		return false, err
//	}
//	return true, nil
//}

// これ以降に実装を追加していく

type hashed struct {
	majorVersion byte
	minorVersion byte
	cost         uint
	salt         []byte
	hash         []byte
}

func GenerateFromPassword(password string, cost uint) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password is empty")
	}
	if len(password) > 72 {
		// TODO エラーにする必要はない
		// bcryptは73文字以降を無視してしまう
		return "", errors.New("password is too long")
	}
	if cost < MinCost || cost > MaxCost {
		// costが0~31なのは、
		// int32の最大値が2147483647で、
		// 0~(2**31-1=2147483647) 回試行する為
		// オーバーフローしてしまうから。
		return "", ErrInvalidCost(cost)
	}

	hashedBytes, err := generateHash([]byte(password), cost)
	return string(hashedBytes), err
}

func generateHash(password []byte, cost uint) ([]byte, error) {
	// 構造体`hashed`の初期化
	p := new(hashed)
	// major versionの付与(2)
	p.majorVersion = majorVersion
	// マイナーバージョンの付与(a/b)
	p.minorVersion = minorVersion
	// コストの付与
	p.cost = cost
	// ソルトの生成
	salt, err := makeSalt()
	if err != nil {
		return nil, err
	}
	p.salt = salt
	// パスワード、コスト、ソルトでハッシュ化する
	hash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}
	p.hash = hash
	// ハッシュ値の生成
	return p.Hash(), nil
}

func makeSalt() ([]byte, error) {
	unencodedSalt := make([]byte, maxSaltSize)
	if _, err := io.ReadFull(rand.Reader, unencodedSalt); err != nil {
		return nil, err
	}

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

func bcrypt(password []byte, cost uint, salt []byte) ([]byte, error) {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
	if err != nil {
		return nil, err
	}

	// この数字の意味は？
	// iは3loop, jは64loopで計192loopする
	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			// ??
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

	// ??
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
		// ??
		blowfish.ExpandKey(ckey, c)
		// ??
		blowfish.ExpandKey(csalt, c)
	}

	return c, nil
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
	copy(arr[n:], p.hash)
	n += encodedHashSize
	// 結果を返却
	return arr[:n]
}
