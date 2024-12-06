package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
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

	// 启动服务
	wg := sync.WaitGroup{}
	runSrv := func(net string) {
		defer wg.Done()
		srv := &dns.Server{Addr: addr, Net: net, Handler: handler}
		logrus.Infof("listen on %s/%s", addr, net)
		if err = srv.ListenAndServe(); err != nil {
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
