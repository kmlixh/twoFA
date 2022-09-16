package twoFA

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"
)

func UnixNanoRandom() int64 { //这里主要想增加一些随机性，从而使生成的密钥在范围内随机偏移
	n, _ := rand.Int(rand.Reader, big.NewInt(200000000))
	n = n.Sub(n, big.NewInt(1000000000))
	return (time.Now().UnixNano() - n.Int64()) / 1000 / 30
}

func HmacSha1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	if total := len(data); total > 0 {
		h.Write(data)
	}
	return h.Sum(nil)
}

func Base32encode(src []byte) string {
	return base32.StdEncoding.EncodeToString(src)
}

func Base32decode(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(s)
}

func Int64ToBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func BytesToUint32(bts []byte) uint32 {
	return (uint32(bts[0]) << 24) + (uint32(bts[1]) << 16) +
		(uint32(bts[2]) << 8) + uint32(bts[3])
}

func genOneTimePassword(key []byte, data []byte) uint32 {
	hash := HmacSha1(key, data)
	offset := hash[len(hash)-1] & 0x0F
	hashParts := hash[offset : offset+4]
	hashParts[0] = hashParts[0] & 0x7F
	number := BytesToUint32(hashParts)
	return number % 1000000
}

// 获取秘钥
func GetSecret() string {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, UnixNanoRandom())
	return strings.ToUpper(Base32encode(HmacSha1(buf.Bytes(), nil)))
}

// 获取动态码
func GetCode(secret string) (string, error) {
	secretUpper := strings.ToUpper(secret)
	secretKey, err := Base32decode(secretUpper)
	if err != nil {
		return "", err
	}
	number := genOneTimePassword(secretKey, Int64ToBytes(time.Now().Unix()/30))
	return fmt.Sprintf("%06d", number), nil
}

// 获取动态码二维码内容
func GetQrCodeData(user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s", user, secret)
}

// 验证动态码
func VerifyCode(secret, code string) (bool, error) {
	_code, err := GetCode(secret)
	if err != nil {
		return false, err
	}
	return _code == code, nil
}
