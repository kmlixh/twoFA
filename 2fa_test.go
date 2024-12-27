package main

import (
	"encoding/base32"
	"strings"
	"testing"
)

func TestGetSecret(t *testing.T) {
	secret := GetSecret()
	if len(secret) < 16 {
		t.Error("secret too short")
	}
	// 验证是否为有效的base32编码
	if _, err := base32.StdEncoding.DecodeString(padSecret(secret)); err != nil {
		t.Error("invalid base32 encoding")
	}
}

func TestGetCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code, err := GetCode(secret)
	if err != nil {
		t.Errorf("GetCode error: %v", err)
	}
	if len(code) != digits {
		t.Errorf("code length should be %d, got %d", digits, len(code))
	}
}

func TestVerifyCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code, _ := GetCode(secret)
	valid, err := VerifyCode(secret, code)
	if err != nil {
		t.Errorf("VerifyCode error: %v", err)
	}
	if !valid {
		t.Error("code should be valid")
	}

	// 测试无效的验证码
	valid, err = VerifyCode(secret, "000000")
	if err != nil {
		t.Errorf("VerifyCode error: %v", err)
	}
	if valid {
		t.Error("invalid code should not be valid")
	}
}

func TestGetQrCodeData(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	account := "test@example.com"
	uri := GetQrCodeData(account, secret)
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Error("invalid URI format")
	}
	if !strings.Contains(uri, secret) {
		t.Error("URI should contain secret")
	}
}
