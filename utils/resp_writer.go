package utils

import (
	"net"

	"github.com/miekg/dns"
)

type FakeRespWriter struct {
	Msg      *dns.Msg
	Bytes    []byte
	remote   net.Addr
	local    net.Addr
	proto    string
	internal bool
}

// NewFakeRespWriter 创建一个FakeRespWriter，用于手动请求dns.Handler时获取DNS响应
func NewFakeRespWriter() *FakeRespWriter {
	return &FakeRespWriter{}
}

// SetRemote 设置远端地址（如DoH场景下使用HTTP客户端的真实地址，而非硬编码的127.0.0.1）
func (w *FakeRespWriter) SetRemote(addr net.Addr) { w.remote = addr }

// SetProto 设置协议标签（如 DoH 的 "https"），供日志展示客户端使用的查询协议
func (w *FakeRespWriter) SetProto(p string) { w.proto = p }

// SetInternal 标记为非客户端请求（如上游DoH域名的内部解析），日志中将跳过
func (w *FakeRespWriter) SetInternal() { w.internal = true }

// Proto 返回协议标签（空表示使用底层连接的网络类型，如 udp/tcp）
func (w *FakeRespWriter) Proto() string { return w.proto }

// Internal 标记该写入器对应的是非客户端请求
func (w *FakeRespWriter) Internal() bool { return w.internal }

func (w *FakeRespWriter) LocalAddr() net.Addr {
	if w.local != nil {
		return w.local
	}
	return &net.IPAddr{IP: []byte{127, 0, 0, 1}}
}

func (w *FakeRespWriter) RemoteAddr() net.Addr {
	if w.remote != nil {
		return w.remote
	}
	return &net.IPAddr{IP: []byte{127, 0, 0, 1}}
}

func (w *FakeRespWriter) WriteMsg(msg *dns.Msg) error {
	w.Msg = msg
	return nil
}

func (w *FakeRespWriter) Write(bytes []byte) (int, error) {
	w.Bytes = bytes
	return len(bytes), nil
}

func (w *FakeRespWriter) Close() error        { return nil }
func (w *FakeRespWriter) TsigStatus() error   { return nil }
func (w *FakeRespWriter) TsigTimersOnly(bool) {}
func (w *FakeRespWriter) Hijack()             {}
