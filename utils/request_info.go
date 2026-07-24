package utils

// RequestMeta 表示 DNS 请求的元数据扩展。
// dns.ResponseWriter 的默认实现不提供 Proto/Internal 方法；
// 实现此接口的写入器（如 FakeRespWriter）可向 handler 传递额外信息。
type RequestMeta interface {
	// Proto 返回协议标签（如 "https"）。空字符串表示使用底层连接的网络类型（udp/tcp）。
	Proto() string

	// Internal 返回 true 表示该请求是内部解析（如上游 DoH 域名解析），
	// 不应计入客户端查询日志。
	Internal() bool
}
