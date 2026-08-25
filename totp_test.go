package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 附录 B Test Vectors
// https://datatracker.ietf.org/doc/html/rfc6238/#appendix-B

// rfc6238Secret 是 RFC 6238 附录 B 测试向量里，SHA1 场景使用的密钥原文（20 字节 ASCII）
// 我们把它转成 Base32，模拟用户从 GitHub 拿到的密钥格式
const rfc6238SecretASCII = "12345678901234567890"

func rfc6238SecretBase32() string {
	return base32.StdEncoding.EncodeToString([]byte(rfc6238SecretASCII))
}

// TestGenerateCodeAt 使用 RFC 6238 官方测试向量验证算法正确性
//
// RFC 6238 附录 B 给的是 8 位验证码，例如 Unix 时间 59 秒时，SHA1 算法下的结果是 "94287082"
// 实现固定输出 6 位，数学上等价于对同一个内部值取 mod 10^6，
// 即取官方 8 位结果的最后 6 位，所以 "94287082" -> "287082"
func TestGenerateCodeAt(t *testing.T) {
	secret := rfc6238SecretBase32()

	cases := []struct {
		unixSeconds int64
		want        string
	}{
		{59, "287082"},         // RFC 8位向量: 94287082
		{1111111109, "081804"}, // RFC 8位向量: 07081804
		{1111111111, "050471"}, // RFC 8位向量: 14050471
		{1234567890, "005924"}, // RFC 8位向量: 89005924
		{2000000000, "279037"}, // RFC 8位向量: 69279037
	}

	for _, c := range cases {
		tm := time.Unix(c.unixSeconds, 0).UTC()
		got, err := generateCodeAt(secret, tm)
		if err != nil {
			t.Fatalf("unix=%d: 生成验证码出错: %v", c.unixSeconds, err)
		}
		if got != c.want {
			t.Errorf("unix=%d: got %s, want %s", c.unixSeconds, got, c.want)
		}
	}
}

// 校验空密钥要正确返回错误，而不是 panic 或返回垃圾结果
func TestGenerateCode_EmptySecret(t *testing.T) {
	_, err := GenerateCode("")
	if err == nil {
		t.Fatal("期望空密钥返回错误，实际没有报错")
	}
}

// 校验非法 base32 字符要报错
func TestGenerateCode_InvalidBase32(t *testing.T) {
	_, err := GenerateCode("这不是base32")
	if err == nil {
		t.Fatal("期望非法 base32 密钥返回错误，实际没有报错")
	}
}

// 校验密钥容错：带空格、不带 padding 也能正确解析
func TestGenerateCode_TolerateSpacesAndNoPadding(t *testing.T) {
	full := rfc6238SecretBase32() // 标准 base32，带 padding
	// 手动插入空格、去掉末尾的 '=' padding，模拟用户从网页抄写密钥的常见情况
	noPad := trimPadding(full)
	spaced := insertSpaces(noPad)

	tm := time.Unix(59, 0).UTC()

	want, err := generateCodeAt(full, tm)
	if err != nil {
		t.Fatalf("基准密钥生成失败: %v", err)
	}

	got, err := generateCodeAt(spaced, tm)
	if err != nil {
		t.Fatalf("带空格无padding密钥生成失败: %v", err)
	}

	if got != want {
		t.Errorf("容错解析结果不一致: got %s, want %s", got, want)
	}
}

// 校验倒计时计算：正好在周期边界和周期中间都要对
func TestRemainingSecondsAt(t *testing.T) {
	cases := []struct {
		unixSeconds int64
		want        int
	}{
		{0, 30},  // 周期刚开始，剩余整整 30 秒
		{29, 1},  // 还剩 1 秒
		{30, 30}, // 下一个周期刚开始
		{59, 1},
	}
	for _, c := range cases {
		got := remainingSecondsAt(time.Unix(c.unixSeconds, 0).UTC())
		if got != c.want {
			t.Errorf("unix=%d: got %d, want %d", c.unixSeconds, got, c.want)
		}
	}
}

// 校验默认生成的密钥长度符合预期，且能被自己的解码逻辑正确解析
func TestGenerateSecret_DefaultLength(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("生成密钥出错: %v", err)
	}

	// 10 字节 base32（无 padding）编码后应为 16 个字符：ceil(10*8/5) = 16
	if len(secret) != 16 {
		t.Errorf("密钥长度 = %d, 期望 16", len(secret))
	}

	// 生成的密钥必须能立刻拿去用，跑一次 GenerateCode 确认能正常工作
	if _, err := GenerateCode(secret); err != nil {
		t.Errorf("生成的密钥无法用于生成验证码: %v", err)
	}
}

// 校验多次生成的密钥不应重复（基本的随机性检查）
func TestGenerateSecret_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := GenerateSecret()
		if err != nil {
			t.Fatalf("生成密钥出错: %v", err)
		}
		if seen[secret] {
			t.Fatalf("生成了重复的密钥: %s", secret)
		}
		seen[secret] = true
	}
}

// 校验字节数过小时会被拒绝，而不是悄悄生成弱密钥
func TestGenerateSecretN_RejectsTooShort(t *testing.T) {
	if _, err := generateSecretN(4); err == nil {
		t.Fatal("期望字节数过小时返回错误，实际没有报错")
	}
}

func trimPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

func insertSpaces(s string) string {
	// 每 4 个字符插一个空格，模拟常见的密钥展示格式
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && i%4 == 0 {
			out = append(out, ' ')
		}
		out = append(out, c)
	}
	return string(out)
}
