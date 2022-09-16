package twoFA

import (
	"fmt"
	"testing"
)

type Tt struct {
	name string
	t    func(t *testing.T)
}

func Test_All(t *testing.T) {
	tests := []Tt{
		{"生成secret测试", func(t *testing.T) {
			secret := GetSecret()
			if secret == "" {
				t.Error("生成密钥出错")
			}
			fmt.Println("secret:", secret)
		}},
		{"生成secret测试", func(t *testing.T) {
			secret := "WRO4QNSWJZLKTG6LYFWQLQQAR3N3DCMR"
			code, er := GetCode(secret)
			if er != nil {
				fmt.Println(er)
				t.Failed()
			}
			fmt.Println("code:", code)
		}},
		{"生成code并验证", func(t *testing.T) {
			secret := "WRO4QNSWJZLKTG6LYFWQLQQAR3N3DCMR"
			code, er := GetCode(secret)
			if er != nil {
				fmt.Println(er)
				t.Failed()
			}
			result, er := VerifyCode(secret, code) //极小的概率会在临界点失败，这里默认不失败
			if !result || er != nil {
				t.Failed()
			}
			fmt.Println("code:", code)
		}},
		{"生成Qrcode所需的字符串", func(t *testing.T) {
			secret := "WRO4QNSWJZLKTG6LYFWQLQQAR3N3DCMR"
			qrData := GetQrCodeData("test", secret)
			if len(qrData) == 0 {
				t.Failed()
			}
			fmt.Println(qrData)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.t)
	}
}
