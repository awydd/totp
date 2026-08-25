package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/awydd/totp"
)

func main() {
	var secret string
	var generate bool
	flag.StringVar(&secret, "secret", "", "TOTP 密钥（Base32 编码，如 JBSWY3DPEHPK3PXP）")
	flag.BoolVar(&generate, "generate", false, "生成一个新的随机密钥并退出")

	// 自定义 -h/--help 的输出文案
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "2fa: 命令行 TOTP 验证码生成器")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  2fa -secret <BASE32密钥>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "参数:")
		flag.PrintDefaults()
	}

	flag.Parse()

	// -generate 是一个独立的"子行为"，优先处理，处理完直接退出，不走后面显示验证码的逻辑
	if generate {
		newSecret, err := totp.GenerateSecret()
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(newSecret)
		return
	}

	// 校验必填参数
	if secret == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须提供 -secret 参数")
		fmt.Fprintln(os.Stderr, "")
		flag.Usage()
		os.Exit(1)
	}

	// 提前跑一次，密钥不合法就直接报错退出，不用等到进入循环
	if _, err := totp.GenerateCode(secret); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	run(ctx, secret)

}

// run 每秒刷新一次显示，直到 ctx 被取消（Ctrl+C）
func run(ctx context.Context, secret string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	printCode(secret) // 先立即显示一次，不用等第一次 tick

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n已退出")
			return
		case <-ticker.C:
			printCode(secret)
		}
	}
}

// printCode 打印当前验证码和剩余秒数，用 \r 让输出在同一行刷新，而不是每秒滚动一条新的
func printCode(secret string) {
	code, err := totp.GenerateCode(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\r生成验证码出错: %v\n", err)
		return
	}
	remaining := totp.RemainingSeconds()

	// \r 回到行首覆盖上一次输出；%-2d 左对齐补齐，避免"剩余秒数"从两位数变一位数时行尾留字符
	fmt.Printf("\r验证码: %s   剩余 %-2d 秒过期", code, remaining)
}
