package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/soheilhy/cmux"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/inbound"
)

// VERSION 程序版本号
var VERSION = "dev"

func main() {
	file, err := os.OpenFile("ts-dns.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal(err)
	}
	defer file.Close()

	// 使用 MultiWriter 同时写入到控制台和文件
	logrus.SetOutput(io.MultiWriter(os.Stdout, file))

	// 读取命令行参数
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	filename := flag.String("c", "ts-dns.toml", "config file path")
	listen := flag.String("listen", "", "listen address/port/protocol")
	showVer := flag.Bool("v", false, "show version and exit")
	debugMode := flag.Bool("vv", false, "show debug log")
	
	flag.Parse()

	if *showVer { // 显示版本号并退出
		fmt.Println(VERSION)
		os.Exit(0)
	}
	if *debugMode {
		logrus.SetLevel(logrus.DebugLevel)
	}
	// 读取配置文件
	conf := config.Conf{}
	if _, err := toml.DecodeFile(*filename, &conf); err != nil {
		logrus.Fatalf("load config file %q failed: %+v", *filename, err)
	}
	buf := bytes.NewBuffer(nil)
	_ = toml.NewEncoder(buf).Encode(conf)
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
		logrus.Fatalf("unknown network: %q", network)
	}
	// 构建handler
	handler, err := inbound.NewHandler(conf)
	if err != nil {
		logrus.Fatalf("build handler failed: %+v", err)
	}
	// 监听SIGNUP命令
	signCh := make(chan os.Signal, 1)
	signal.Notify(signCh, syscall.SIGHUP)
	go reloadConf(signCh, filename, handler)

	run(&conf, handler, addr, network)
}

func run(conf *config.Conf, handler inbound.IHandler, addr, network string) {
	// Check if SSL certificate and key files are configured to enable DoH
	enableDoh := conf.SSLCertFile != "" && conf.SSLKeyFile != ""

	if !enableDoh {
		// original logic without doh
		wg := sync.WaitGroup{}
		runSrv := func(net string) {
			defer wg.Done()
			srv := &dns.Server{Addr: addr, Net: net, Handler: handler}
			logrus.Infof("listen on %s/%s", addr, net)
			if err := srv.ListenAndServe(); err != nil {
				logrus.Errorf("service stopped: %+v", err)
			}
		}
		if network != "" {
			wg.Add(1)
			go runSrv(network)
		} else {
			wg.Add(2)
			go runSrv("udp")
			go runSrv("tcp")
		}
		wg.Wait()
		logrus.Infof("ts-dns exists")
		return
	}

	// new logic with cmux
	certFile, keyFile := expandHome(conf.SSLCertFile), expandHome(conf.SSLKeyFile)
	if _, err := os.Stat(certFile); err != nil {
		logrus.Warnf("cert file not found, fallback to non-doh mode: %s", certFile)
		// Create a temporary config without SSL to run without DoH
		tempConf := *conf
		tempConf.SSLCertFile = ""
		tempConf.SSLKeyFile = ""
		run(&tempConf, handler, addr, network)
		return
	}
	if _, err := os.Stat(keyFile); err != nil {
		logrus.Warnf("key file not found, fallback to non-doh mode: %s", keyFile)
		// Create a temporary config without SSL to run without DoH
		tempConf := *conf
		tempConf.SSLCertFile = ""
		tempConf.SSLKeyFile = ""
		run(&tempConf, handler, addr, network)
		return
	}

	wg := sync.WaitGroup{}
	// start udp server
	if network == "" || network == "udp" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Tune UDP buffer size
			lc := net.ListenConfig{}
			pc, err := lc.ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				logrus.Fatalf("listen on %s/udp failed: %v", addr, err)
			}
			if udpConn, ok := pc.(*net.UDPConn); ok {
				_ = udpConn.SetReadBuffer(2 * 1024 * 1024)  // 2MB
				_ = udpConn.SetWriteBuffer(2 * 1024 * 1024) // 2MB
			}
			srv := &dns.Server{PacketConn: pc, Handler: handler}
			logrus.Infof("listen on %s/udp", addr)
			if err := srv.ActivateAndServe(); err != nil {
				logrus.Fatalf("udp service stopped: %+v", err)
			}
		}()
	}

	// start multiplexer on tcp
	if network == "" || network == "tcp" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			logrus.Fatalf("listen on %s/tcp failed: %v", addr, err)
		}
		defer l.Close()

		m := cmux.New(l)
		m.SetReadTimeout(time.Second * 5) // Prevent Slowloris attacks on cmux level
		tlsListener := m.Match(cmux.TLS())
		anyListener := m.Match(cmux.Any())

		// start doh server
		dohHandler := inbound.NewDohHandler(handler)
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
			logrus.Fatalf("load cert failed: %v", err)
		}
		dohServer := &http.Server{
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

		// Watch for certificate changes if ReloadConfig is called
		go func() {
			for {
				time.Sleep(time.Minute * 10) // Optional: period check
				if _, err := loadCert(); err != nil {
					logrus.Errorf("reload cert failed: %v", err)
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			logrus.Infof("listen on %s/dns-query", addr)
			if err := dohServer.ServeTLS(tlsListener, "", ""); err != nil && err != http.ErrServerClosed {
				logrus.Fatalf("doh service stopped: %+v", err)
			}
		}()

		// start tcp dns server
		wg.Add(1)
		go func() {
			defer wg.Done()
			logrus.Infof("listen on %s/tcp", addr)
			if err := dns.ActivateAndServe(anyListener, nil, handler); err != nil {
				logrus.Fatalf("tcp service stopped: %+v", err)
			}
		}()

		logrus.Infof("start cmux server on %s", addr)
		if err := m.Serve(); err != nil {
			logrus.Fatalf("cmux server failed: %v", err)
		}
	}

	wg.Wait()
	logrus.Infof("ts-dns exists")
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

func reloadConf(ch chan os.Signal, filename *string, handler inbound.IHandler) {
	for {
		<-ch
		conf := config.Conf{}
		if _, err := toml.DecodeFile(*filename, &conf); err != nil {
			logrus.Warnf("load config file %q failed: %+v", *filename, err)
			continue
		}
		buf := bytes.NewBuffer(nil)
		_ = toml.NewEncoder(buf).Encode(conf)
		logrus.Debugf("reload config: %s", buf)
		if err := handler.ReloadConfig(conf); err != nil {
			logrus.Warnf("reload config failed: %+v", err)
			continue
		}
		logrus.Infof("reload config success")
	}
}
