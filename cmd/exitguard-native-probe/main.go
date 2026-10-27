// The probe is observational. It cannot change ExitGuard's armed state and
// there is no command that imports its output as a protection certificate.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"exitguard/internal/nativeapp"
	"exitguard/internal/nativeprobe"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Native probe:", err)
		os.Exit(1)
	}
}
func run() error {
	box := flag.String("box", "", "明确的产品箱名")
	child := flag.Bool("child", false, "重新命名的子进程观测")
	controls := flag.Bool("host-controls", false, "在箱外监听三个本地对照端口")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("不接受额外参数")
	}
	if *controls {
		return hostControls()
	}
	if *box != "ExitGuard_Chrome" && *box != "ExitGuard_Edge" && *box != "ExitGuard_Claude" {
		return errors.New("请经官方 Start.exe /box:产品箱 启动；必须指定 --box")
	}
	watchdog := time.AfterFunc(55*time.Second, func() {
		fmt.Fprintln(os.Stderr, "探针超时；观察不完整。没有完整保护结论。")
		os.Exit(2)
	})
	defer watchdog.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	actual, flags, err := nativeapp.Membership(ctx, uint32(os.Getpid()))
	if err != nil {
		return err
	}
	if actual != *box {
		return errors.New("实际驱动箱归属与要求不符；不进行网络测试")
	}
	result := map[string]any{"schema": "exitguard-native-observations-v1", "state": "incomplete", "pid": os.Getpid(), "box": actual, "processFlags": flags, "renamedChild": *child, "notice": "只有实际观测，没有完整保护结论。连接失败不自动表示阻断；需配合箱外监听/网络抓取对照。DNS broker、异常断线及三款应用验收仍未完成。"}
	proxy, _ := url.Parse("http://127.0.0.1:17890")
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, proxyErr := client.Get("https://api.ipify.org?format=json")
	if proxyErr != nil {
		result["explicitProxyHTTPError"] = proxyErr.Error()
	} else {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 512))
		response.Body.Close()
		result["explicitProxyHTTPStatus"] = response.StatusCode
		result["explicitProxyIPResponse"] = string(body)
		if readErr != nil {
			result["explicitProxyReadError"] = readErr.Error()
		}
	}
	transport.CloseIdleConnections()
	for name, address := range map[string]string{"guardTCP": "127.0.0.1:17890", "otherLoopbackTCP": "127.0.0.1:17892", "ipv6LoopbackTCP": "[::1]:17892", "directIPv4TCP": "1.1.1.1:443", "directIPv6TCP": "[2606:4700:4700::1111]:443"} {
		result[name] = nativeprobe.TCP(address, 1500*time.Millisecond)
	}
	udp, err := net.DialTimeout("udp4", "127.0.0.1:17893", time.Second)
	if err != nil {
		result["udpError"] = err.Error()
	} else {
		_ = udp.SetDeadline(time.Now().Add(time.Second))
		n, writeErr := udp.Write([]byte("ExitGuard-local-echo-control"))
		result["udpBytesAcceptedBySocket"] = n
		result["udpLocalEndpoint"] = udp.LocalAddr().String()
		if writeErr != nil {
			result["udpWriteError"] = writeErr.Error()
		}
		var b [128]byte
		n, readErr := udp.Read(b[:])
		result["udpReplyBytes"] = n
		if readErr != nil {
			result["udpReplyError"] = readErr.Error()
		}
		udp.Close()
	}
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	name := hex.EncodeToString(entropy[:]) + ".example.com"
	result["dns"] = dnsObservations(name)
	if !*child {
		source, err := os.Executable()
		if err != nil {
			return err
		}
		directory, err := os.MkdirTemp("", "ExitGuard-renamed-child-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(directory)
		path := filepath.Join(directory, "new-name-"+hex.EncodeToString(entropy[:])+".exe")
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		input.Close()
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("无法创建重新命名的子进程探针")
		}
		command := exec.CommandContext(ctx, path, "--box", *box, "--child")
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			result["childError"] = err.Error()
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func hostControls() error {
	// Refuse to mislabel a boxed control as an unaffected ordinary application.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := nativeapp.RequireUnboxed(ctx); err != nil {
		return err
	}
	tcp4, err := net.Listen("tcp4", "127.0.0.1:17892")
	if err != nil {
		return err
	}
	defer tcp4.Close()
	tcp6, err := net.Listen("tcp6", "[::1]:17892")
	if err != nil {
		return err
	}
	defer tcp6.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:17893")
	if err != nil {
		return err
	}
	defer udp.Close()
	var tcp4Count, tcp6Count, udpCount atomic.Uint64
	for index, listener := range []net.Listener{tcp4, tcp6} {
		count := &tcp4Count
		protocol := "tcp4"
		if index == 1 {
			count = &tcp6Count
			protocol = "tcp6"
		}
		go func(l net.Listener, count *atomic.Uint64, protocol string) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				fmt.Printf("HOST_RECEIVED protocol=%s count=%d peer=%s\n", protocol, count.Add(1), c.RemoteAddr().String())
				c.Close()
			}
		}(listener, count, protocol)
	}
	go func() {
		var b [512]byte
		for {
			n, addr, err := udp.ReadFrom(b[:])
			if err != nil {
				return
			}
			fmt.Printf("HOST_RECEIVED protocol=udp4 count=%d bytes=%d peer=%s\n", udpCount.Add(1), n, addr.String())
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()
	fmt.Println("箱外本地对照已监听 127.0.0.1:17892 / [::1]:17892 TCP 和 127.0.0.1:17893 UDP。保持此窗口；Ctrl+C 结束。没有修改任何系统网络设置。")
	select {}
}
