package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/soheilhy/cmux"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/inbound"
)

// VERSION 程序版本号
var VERSION = "dev"

func main() {
	exitCode := 0
	defer func() {
		os.Exit(exitCode)
	}()

	// 读取命令行参数
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	filename := flag.String("c", "ts-dns.yaml", "config file path")
	listen := flag.String("listen", "", "listen address/port/protocol")
	showVer := flag.Bool("v", false, "show version and exit")
	debugMode := flag.Bool("vv", false, "show debug log")
	logFile := flag.String("log", "ts-dns.log", "log file path")

	flag.Parse()

	if *showVer { // 显示版本号并退出
		fmt.Println(VERSION)
		os.Exit(0)
	}

	file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		logrus.Error(err)
		exitCode = 1
		return
	}
	defer file.Close()

	// 配置日志格式：时间 + 级别 + 消息
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		DisableColors:   true, // 文件输出不需要颜色转义
	})
	// 使用 MultiWriter 同时写入到控制台和文件
	logrus.SetOutput(io.MultiWriter(os.Stdout, file))

	if *debugMode {
		logrus.SetLevel(logrus.DebugLevel)
	}
	// 读取配置文件
	conf := config.Conf{}
	yamlBytes, err := os.ReadFile(*filename)
	if err != nil {
		logrus.Errorf("read config file %q failed: %+v", *filename, err)
		exitCode = 1
		return
	}
	if err := yaml.Unmarshal(yamlBytes, &conf); err != nil {
		logrus.Errorf("load config file %q failed: %+v", *filename, err)
		exitCode = 1
		return
	}
	normalizeConf(&conf)
	buf := bytes.NewBuffer(nil)
	_ = yaml.NewEncoder(buf).Encode(conf)
	logrus.Debugf("load config success: %s", buf)
	// 解析监听地址
	if *listen == "" {
		listen = &conf.Listen
	}
	addr, network := *listen, ""
	if parts := strings.SplitN(*listen, "/", 2); len(parts) == 2 {
		addr, network = parts[0], strings.ToLower(parts[1])
	}
	if network != "" && network != "udp" && network != "tcp" {
		logrus.Errorf("unknown network: %q", network)
		exitCode = 1
		return
	}
	// 构建handler
	handler, err := inbound.NewHandler(conf)
	if err != nil {
		logrus.Errorf("build handler failed: %+v", err)
		exitCode = 1
		return
	}
	defer handler.Stop()

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 监听SIGHUP信号
	signCh := make(chan os.Signal, 1)
	signal.Notify(signCh, syscall.SIGHUP)
	defer signal.Stop(signCh)
	go reloadConf(runCtx, signCh, filename, handler)

	if err := run(runCtx, &conf, handler, addr, network); err != nil {
		logrus.Errorf("ts-dns stopped: %+v", err)
		exitCode = 1
		return
	}
}

func run(ctx context.Context, conf *config.Conf, handler inbound.IHandler, addr, network string) error {
	// Check if SSL certificate and key files are configured to enable DoH
	enableDoh := conf.SSLCertFile != "" && conf.SSLKeyFile != ""
	certFile, keyFile := expandHome(conf.SSLCertFile), expandHome(conf.SSLKeyFile)
	if enableDoh {
		if _, err := os.Stat(certFile); err != nil {
			logrus.Warnf("cert file not found, disable DoH: %s", certFile)
			enableDoh = false
		} else if _, err := os.Stat(keyFile); err != nil {
			logrus.Warnf("key file not found, disable DoH: %s", keyFile)
			enableDoh = false
		}
	}

	// 明文 HTTP DoH（反向代理用）：listen_doh_http 指定端口即开启，固定绑 127.0.0.1:<port>
	dohHTTPAddr := ""
	if conf.ListenDoHHTTP != 0 {
		dohHTTPAddr = "127.0.0.1:" + strconv.Itoa(conf.ListenDoHHTTP)
	}

	// 单端口模式（cmux 复用 udp/tcp/doh），可附加明文 HTTP DoH（反向代理用）
	if !enableDoh {
		return runPlain(ctx, handler, addr, network, dohHTTPAddr)
	}
	return runDoH(ctx, handler, addr, network, certFile, keyFile, dohHTTPAddr)
}

func runPlain(ctx context.Context, handler inbound.IHandler, addr, network, dohHTTPAddr string) error {
	type dnsRuntime struct {
		name string
		srv  *dns.Server
	}

	var runtimes []dnsRuntime
	addUDP := func() error {
		lc := net.ListenConfig{}
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s/udp failed: %w", addr, err)
		}
		if udpConn, ok := pc.(*net.UDPConn); ok {
			_ = udpConn.SetReadBuffer(2 * 1024 * 1024)
			_ = udpConn.SetWriteBuffer(2 * 1024 * 1024)
		}
		runtimes = append(runtimes, dnsRuntime{name: "udp", srv: &dns.Server{PacketConn: pc, Handler: handler}})
		return nil
	}
	addTCP := func() error {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s/tcp failed: %w", addr, err)
		}
		runtimes = append(runtimes, dnsRuntime{name: "tcp", srv: &dns.Server{Listener: l, Handler: handler}})
		return nil
	}
	closeRuntimes := func() {
		for _, runtime := range runtimes {
			_ = shutdownDNSServer(context.Background(), runtime.srv)
		}
	}

	if network == "" || network == "udp" {
		if err := addUDP(); err != nil {
			return err
		}
	}
	if network == "" || network == "tcp" {
		if err := addTCP(); err != nil {
			closeRuntimes()
			return err
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 16) // 足够容纳所有可能 goroutine 上报的错误（当前上限约 6），避免阻塞
	plainDoH := startPlaintextDoH(handler, dohHTTPAddr, &wg, errCh)
	for _, runtime := range runtimes {
		runtime := runtime
		wg.Add(1)
		go func() {
			defer wg.Done()
			logrus.Infof("listen on %s/%s", addr, runtime.name)
			if err := runtime.srv.ActivateAndServe(); err != nil && !isServerClosed(err) {
				errCh <- fmt.Errorf("%s service stopped: %w", runtime.name, err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	shutdownRuntimes := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, runtime := range runtimes {
			_ = shutdownDNSServer(shutdownCtx, runtime.srv)
		}
	}
	select {
	case <-ctx.Done():
		shutdownRuntimes()
		shutdownHTTPServer(plainDoH, "doh-http")
		<-done
		logrus.Infof("ts-dns exited")
		return nil
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			logrus.Infof("ts-dns exited")
			return nil
		}
	case err := <-errCh:
		shutdownRuntimes()
		shutdownHTTPServer(plainDoH, "doh-http")
		<-done
		return err
	}
}

func runDoH(ctx context.Context, handler inbound.IHandler, addr, network, certFile, keyFile, dohHTTPAddr string) error {

	wg := sync.WaitGroup{}
	errCh := make(chan error, 16) // 足够容纳所有可能 goroutine 上报的错误（当前上限约 6），避免阻塞
	var udpServer *dns.Server
	var dohServer *http.Server
	var plainDoH *http.Server
	var mux cmux.CMux
	var tcpListener net.Listener
	var certDone chan struct{}
	// start udp server
	if network == "" || network == "udp" {
		lc := net.ListenConfig{}
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return fmt.Errorf("listen on %s/udp failed: %w", addr, err)
		}
		if udpConn, ok := pc.(*net.UDPConn); ok {
			_ = udpConn.SetReadBuffer(2 * 1024 * 1024)  // 2MB
			_ = udpConn.SetWriteBuffer(2 * 1024 * 1024) // 2MB
		}
		udpServer = &dns.Server{PacketConn: pc, Handler: handler}
		wg.Add(1)
		go func() {
			defer wg.Done()
			logrus.Infof("listen on %s/udp", addr)
			if err := udpServer.ActivateAndServe(); err != nil && !isServerClosed(err) {
				errCh <- fmt.Errorf("udp service stopped: %w", err)
			}
		}()
	}
	cleanupStarted := func() {
		if udpServer != nil {
			shutdownDNSServer(context.Background(), udpServer)
		}
		wg.Wait()
	}

	// start multiplexer on tcp
	if network == "" || network == "tcp" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			cleanupStarted()
			return fmt.Errorf("listen on %s/tcp failed: %w", addr, err)
		}
		tcpListener = l

		m := cmux.New(l)
		mux = m
		m.SetReadTimeout(time.Second * 5) // Prevent Slowloris attacks on cmux level
		tlsListener := m.Match(cmux.TLS())
		anyListener := m.Match(cmux.Any())

		// start doh server
		dohHandler := inbound.NewDohHandler(handler, false)
		var certPtr atomic.Value
		loadCert := func() (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, err
			}
			certPtr.Store(&cert)
			return &cert, nil
		}
		if _, err := loadCert(); err != nil {
			_ = l.Close()
			cleanupStarted()
			return fmt.Errorf("load cert failed: %w", err)
		}
		dohServer = &http.Server{
			Handler: dohHandler,
			TLSConfig: &tls.Config{
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return certPtr.Load().(*tls.Certificate), nil
				},
				NextProtos: []string{"h2", "http/1.1"}, // Enable HTTP/2
			},
			ReadTimeout:  time.Second * 5,
			WriteTimeout: time.Second * 5,
			IdleTimeout:  time.Second * 30,
		}

		// Watch for certificate changes
		certDone = make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Minute * 10)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if _, err := loadCert(); err != nil {
						logrus.Errorf("reload cert failed: %v", err)
					}
				case <-certDone:
					return
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			logrus.Infof("listen on %s/dns-query", addr)
			if err := dohServer.ServeTLS(tlsListener, "", ""); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("doh service stopped: %w", err)
			}
		}()

		// start tcp dns server
		wg.Add(1)
		go func() {
			defer wg.Done()
			logrus.Infof("listen on %s/tcp", addr)
			if err := dns.ActivateAndServe(anyListener, nil, handler); err != nil {
				if !isServerClosed(err) && !errors.Is(err, cmux.ErrServerClosed) && !errors.Is(err, cmux.ErrListenerClosed) {
					errCh <- fmt.Errorf("tcp service stopped: %w", err)
				}
			}
		}()

		logrus.Infof("start cmux server on %s", addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Serve(); err != nil && !errors.Is(err, cmux.ErrServerClosed) && !errors.Is(err, cmux.ErrListenerClosed) {
				errCh <- fmt.Errorf("cmux server failed: %w", err)
			}
		}()
	}

	// 可选：明文 HTTP DoH（反向代理用），独立于 cmux 之外
	plainDoH = startPlaintextDoH(handler, dohHTTPAddr, &wg, errCh)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if certDone != nil {
			close(certDone)
		}
		shutdownHTTPServer(dohServer, "doh (https)")
		shutdownHTTPServer(plainDoH, "doh-http")
		if udpServer != nil {
			if err := shutdownDNSServer(shutdownCtx, udpServer); err != nil && !isServerClosed(err) {
				logrus.Warnf("shutdown udp server failed: %+v", err)
			}
		}
		if mux != nil {
			mux.Close()
		}
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
	}

	select {
	case <-ctx.Done():
		shutdown()
		<-done
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
		}
	case err := <-errCh:
		shutdown()
		<-done
		return err
	}
	logrus.Infof("ts-dns exited")
	return nil
}

// startPlaintextDoH 启动明文 HTTP DoH 服务（供反向代理使用）。
// 该地址应仅绑 loopback（如 127.0.0.1:53053），由受信任的反向代理转发。
// addr 为空时返回 nil（不启动）。
func startPlaintextDoH(handler inbound.IHandler, addr string, wg *sync.WaitGroup, errCh chan error) *http.Server {
	if addr == "" {
		return nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("listen on %s/dns-query (http) failed: %w", addr, err)
		return nil
	}
	srv := &http.Server{
		Handler:     inbound.NewDohHandler(handler, true),
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		logrus.Infof("listen on %s/dns-query (http, for reverse proxy)", addr)
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("doh-http service stopped: %w", err)
		}
	}()
	return srv
}


func shutdownHTTPServer(srv *http.Server, name string) {
	if srv == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
		logrus.Warnf("shutdown %s failed: %v", name, err)
	}
}

func isServerClosed(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "server closed") || strings.Contains(err.Error(), "use of closed network connection")
}

func shutdownDNSServer(ctx context.Context, srv *dns.Server) error {
	if srv == nil {
		return nil
	}
	err := srv.ShutdownContext(ctx)
	if err == nil || !strings.Contains(err.Error(), "server not started") {
		return err
	}
	if srv.PacketConn != nil {
		return srv.PacketConn.Close()
	}
	if srv.Listener != nil {
		return srv.Listener.Close()
	}
	return err
}

// expandHome expands the path to include the home directory if the path
// starts with `~`. If it doesn't, the path is returned as-is.
func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}

	usr, err := user.Current()
	if err != nil {
		logrus.Warnf("Could not get current user: %v", err)
		return path
	}
	return filepath.Join(usr.HomeDir, path[1:])
}

func reloadConf(ctx context.Context, ch chan os.Signal, filename *string, handler inbound.IHandler) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
		conf := config.Conf{}
		yamlBytes, err := os.ReadFile(*filename)
		if err != nil {
			logrus.Warnf("read config file %q failed: %+v", *filename, err)
			continue
		}
		if err := yaml.Unmarshal(yamlBytes, &conf); err != nil {
			logrus.Warnf("load config file %q failed: %+v", *filename, err)
			continue
		}
		normalizeConf(&conf)
		buf := bytes.NewBuffer(nil)
		_ = yaml.NewEncoder(buf).Encode(conf)
		logrus.Debugf("reload config: %s", buf)
		if err := handler.ReloadConfig(conf); err != nil {
			logrus.Warnf("reload config failed: %+v", err)
			continue
		}
		logrus.Infof("reload config success")
	}
}

func normalizeConf(conf *config.Conf) {
	if conf.QueryTimeout <= 0 && conf.Global.Timeout > 0 {
		conf.QueryTimeout = conf.Global.Timeout
	}
}
