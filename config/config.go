package config

type Conf struct {
	HostsFiles []string          `toml:"hosts_files"`
	Hosts      map[string]string `toml:"hosts"`
	Cache      CacheConf         `toml:"cache"`
	Global     GlobalConf        `toml:"global"`

	Groups        map[string]Group          `toml:"groups"`
	DisableIPv6   bool                      `toml:"disable_ipv6"`
	DisableQTypes []string                  `toml:"disable_qtypes"`
	Redirectors   map[string]RedirectorConf `toml:"redirectors"`

	Listen       string `toml:"listen"`
	QueryTimeout int    `toml:"query_timeout"` // 全局查询超时（秒）
	SSLCertFile  string `toml:"ssl_cert_file"`
	SSLKeyFile   string `toml:"ssl_key_file"`

	// 明文 HTTP DoH 端口（可选）。仅填端口号，ts-dns 固定绑 127.0.0.1:<端口>，
	// 供本机反向代理（如 nginx）终止 TLS 后转发 /dns-query 使用；ts-dns 通过
	// X-Forwarded-For / X-Forwarded-Proto 还原真实客户端地址与协议。
	// 留空(0)则不开启；主 listen 仍按原方式同时提供 udp/tcp/(https)doh。
	ListenDoHHTTP int `toml:"listen_doh_http"`
}

// GlobalConf 兼容旧配置文件中的 global section
type GlobalConf struct {
	HTTPTimeout int `toml:"http_timeout"`
	Timeout     int `toml:"timeout"`
}

// CacheConf 配置文件中cache section对应的结构
type CacheConf struct {
	Size   int `toml:"size"`
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

// Group 配置文件中每个groups section对应的结构
type Group struct {
	DisableIPv6   bool     `toml:"disable_ipv6"`
	DisableQTypes []string `toml:"disable_qtypes"`
	ECS           string   `toml:"ecs"`
	NoCookie      bool     `toml:"no_cookie"`

	Rules         []string `toml:"rules"`
	RulesFile     string   `toml:"rules_file"`
	GFWListFile   string   `toml:"gfwlist_file"`
	GFWListURL    string   `toml:"gfwlist_url"`
	GFWListUpdate string   `toml:"gfwlist_update"` // gfwlist_url 更新周期，支持 m/h/d（如 30m、1h、2d），默认 1h
	Fallback      bool     `toml:"fallback"`

	Socks5 string `toml:"socks5"`

	DNS    []string `toml:"dns"`
	DoT    []string `toml:"dot"`
	DoH    []string `toml:"doh"`
	Hijack []string `toml:"hijack"`

	FastestIP           bool `toml:"fastest_ip"`
	TCPPingPort         int  `toml:"tcp_ping_port"`
	FastestPingTimeoutMs int  `toml:"fastest_ping_timeout_ms"`
	FastestPingMaxIPs    int  `toml:"fastest_ping_max_ips"`

	IPSet    string `toml:"ipset"`
	IPSet6   string `toml:"ipset6"`
	IPSetTTL int    `toml:"ipset_ttl"`

	Redirector string `toml:"redirector"`
}

func (g Group) IsSetGFWList() bool {
	return g.GFWListFile != "" || g.GFWListURL != ""
}

func (g Group) IsEmptyRule() bool {
	return len(g.Rules) == 0 && g.RulesFile == "" && !g.IsSetGFWList()
}

// RedirectorConf 重定向器配置
type RedirectorConf struct {
	Type      string   `toml:"type"`
	Rules     []string `toml:"rules"`
	RulesFile string   `toml:"rules_file"`
	DstGroup  string   `toml:"dst_group"`
}
