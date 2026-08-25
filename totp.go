package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// 步长（秒）
	DefaultPeriod = 30
	// 验证码位数
	DefaultDigits = 6
	// 密钥字节数
	DefaultSecretBytes = 10
)

// 使用变量而不直接使用 time.Now()，方便测试中临时替换： nowFunc = func() time.Time { return fixedTime }
var nowFunc = time.Now

var ErrEmptySecret = errors.New("totp: secret can not be empty")

func GenerateCode(secret string) (string, error) {
	return generateCodeAt(secret, nowFunc())
}

// 根据指定时间 t 生成验证码
// 主要用于单元测试（可以传入固定时间戳）
func generateCodeAt(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}

	// 时间计数器，从 Unix 纪元起，经过了第几个 30 秒周期
	counter := uint64(t.Unix()) / DefaultPeriod

	return hotp(key, counter, DefaultDigits), nil
}

// 返回当前验证码距离过期还剩多少秒，用于命令行倒计时显示
func RemainingSeconds() int {
	return remainingSecondsAt(nowFunc())
}

// RemainingSeconds 的可测试版本
func remainingSecondsAt(t time.Time) int {
	elapsed := int(t.Unix() % DefaultPeriod)
	return DefaultPeriod - elapsed
}

// 生成一个新的 TOTP 密钥，使用默认长度（10 字节 = 80 位熵）
// 返回的字符串是 Base32 编码、不带 padding，可以直接展示给用户抄写，
// 或者拼进 otpauth:// URL 里生成二维码
func GenerateSecret() (string, error) {
	return generateSecretN(DefaultSecretBytes)
}

// generateSecretN 生成一个新的 TOTP 密钥，n 是原始随机字节数（不是编码后的字符串长度）
//
// n 越大熵越高越安全，但用户手动输入的负担也越大；
// 常见取值
// * 10（80位，Google Authenticator 惯例）
// * 16（128位，RFC 4226 建议下限）
// * 20（160位，等于 SHA1 输出长度）
func generateSecretN(n int) (string, error) {
	if n < DefaultSecretBytes {
		// 低于 10 字节（80位）容易被暴力破解，直接拒绝而不是悄悄生成弱密钥
		return "", fmt.Errorf("totp: 密钥字节数至少为 %d，得到 %d", DefaultSecretBytes, n)
	}

	raw := make([]byte, n)
	//! 必须用 crypto/rand，而不是 math/rand —— 后者是可预测的伪随机数
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("totp: 生成随机密钥失败: %w", err)
	}

	// NoPadding 省去末尾的 '=' 符号，用户抄写、放进二维码 URL 时更干净
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// 把用户输入的 Base32 密钥字符串解码成原始字节
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimSpace(secret))
	// 删除掉空格
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return nil, ErrEmptySecret
	}

	// Base32 编码要求长度是 8 的倍数，不足的用 '=' 补齐
	if rem := len(s) % 8; rem != 0 {
		s += strings.Repeat("=", 8-rem)
	}

	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: 密钥不是合法的 base32 编码: %w", err)
	}
	return key, nil
}

// 实现 RFC 4226 的 HOTP 算法
// 对 counter 做 HMAC 签名，再做动态截断得到 N 位数字
// TOTP 就是 "把 counter 换成时间算出来的值" 的 HOTP
func hotp(key []byte, counter uint64, digits int) string {
	// counter 转成 8 字节大端序，作为 HMAC 的消息体
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	// HMAC-SHA1 签名，得到 20 字节摘要
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)

	// 动态截断：用摘要最后一个字节的低 4 位作为偏移量（取值范围 0~15）
	offset := sum[len(sum)-1] & 0x0f

	// 从偏移量位置取 4 个字节，组成一个 31 位整数（清掉最高位，避免符号问题）
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	// 对 10^digits 取模，得到最终的 N 位数字
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	otp := code % mod

	// 位数不足时前面补 0（比如 "26825" 要补成 "026825"）
	return fmt.Sprintf("%0*d", digits, otp)
}
