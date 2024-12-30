package twoFA

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	digits = 6  // TOTP码的位数
	period = 30 // TOTP的时间窗口(秒)
	skew   = 1  // 允许的时间偏差单位
)

// GetSecret 生成随机的2FA密钥
func GetSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// GetCode 根据密钥生成当前时间的TOTP码
func GetCode(secret string) (string, error) {
	// 解码base32密钥
	key, err := base32.StdEncoding.DecodeString(padSecret(secret))
	if err != nil {
		return "", fmt.Errorf("invalid secret: %v", err)
	}

	// 获取当前时间戳
	counter := uint64(time.Now().Unix() / period)

	return generateCode(key, counter), nil
}

// VerifyCode 验证TOTP码是否有效
func VerifyCode(secret, code string) (bool, error) {
	key, err := base32.StdEncoding.DecodeString(padSecret(secret))
	if err != nil {
		return false, fmt.Errorf("invalid secret: %v", err)
	}

	// 获取当前时间戳
	now := time.Now().Unix()
	counter := now / period

	// 检查前后时间窗口的码
	for i := -skew; i <= skew; i++ {
		if generateCode(key, uint64(counter+int64(i))) == code {
			return true, nil
		}
	}

	return false, nil
}

// GetQrCodeData 生成用于二维码的URI
func GetQrCodeData(account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s",
		url.QueryEscape(account),
		secret)
}

// generateCode 根据密钥和计数器生成TOTP码
func generateCode(key []byte, counter uint64) string {
	// 将计数器转换为字节数组
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, counter)

	// 计算HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(b)
	hash := h.Sum(nil)

	// 获取偏移量
	offset := hash[len(hash)-1] & 0xf

	// 生成4字节的代码
	binary := binary.BigEndian.Uint32(hash[offset : offset+4])
	binary &= 0x7fffffff

	// 取模得到指定位数的代码
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := binary % mod

	// 格式化为固定位数的字符串
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}

// padSecret 补全base32编码的等号
func padSecret(secret string) string {
	if m := len(secret) % 8; m != 0 {
		secret += strings.Repeat("=", 8-m)
	}
	return secret
}
