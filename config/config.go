package config

type Conf struct {
	HostsFiles []string          `yaml:"hosts_files"`
	Hosts      map[string]string `yaml:"hosts"`
	Cache      CacheConf         `yaml:"cache"`
	Global     GlobalConf        `yaml:"global"`

	Groups        map[string]Group          `yaml:"groups"`
	DisableIPv6   bool                      `yaml:"disable_ipv6"`
	DisableQTypes []string                  `yaml:"disable_qtypes"`
	Redirectors   map[string]RedirectorConf `yaml:"redirectors"`

	Listen       string `yaml:"listen"`
	QueryTimeout int    `yaml:"query_timeout"` // 全局查询超时（秒）
	SSLCertFile  string `yaml:"ssl_cert_file"`
	SSLKeyFile   string `yaml:"ssl_key_file"`

	// 明文 HTTP DoH 端口（可选）。仅填端口号，ts-dns 固定绑 127.0.0.1:<端口>，
	// 供本机反向代理（如 nginx）终止 TLS 后转发 /dns-query 使用；ts-dns 通过
	// X-Forwarded-For / X-Forwarded-Proto 还原真实客户端地址与协议。
	// 留空(0)则不开启；主 listen 仍按原方式同时提供 udp/tcp/(https)doh。
	ListenDoHHTTP int `yaml:"listen_doh_http"`
}

// GlobalConf 兼容旧配置文件中的 global section
type GlobalConf struct {
	HTTPTimeout int `yaml:"http_timeout"`
	Timeout     int `yaml:"timeout"`
}

// CacheConf 配置文件中cache section对应的结构
type CacheConf struct {
	Size   int `yaml:"size"`
	MinTTL int `yaml:"min_ttl"`
	MaxTTL int `yaml:"max_ttl"`
}

// Group 配置文件中每个groups section对应的结构
type Group struct {
	DisableIPv6   bool     `yaml:"disable_ipv6"`
	DisableQTypes []string `yaml:"disable_qtypes"`
	ECS           string   `yaml:"ecs"`
	NoCookie      bool     `yaml:"no_cookie"`

	Rules         []string `yaml:"rules"`
	RulesFile     string   `yaml:"rules_file"`
	GFWListFile   string   `yaml:"gfwlist_file"`
	GFWListURL    string   `yaml:"gfwlist_url"`
	GFWListUpdate string   `yaml:"gfwlist_update"` // gfwlist_url 更新周期，支持 m/h/d（如 30m、1h、2d），默认 1h
	Fallback      bool     `yaml:"fallback"`

	Socks5 string `yaml:"socks5"`

	DNS    []string `yaml:"dns"`
	DoT    []string `yaml:"dot"`
	DoH    []string `yaml:"doh"`
	Hijack []string `yaml:"hijack"`

	FastestIP            bool `yaml:"fastest_ip"`
	TCPPingPort          int  `yaml:"tcp_ping_port"`
	FastestPingTimeoutMs int  `yaml:"fastest_ping_timeout_ms"`
	FastestPingMaxIPs    int  `yaml:"fastest_ping_max_ips"`

	IPSet    string `yaml:"ipset"`
	IPSet6   string `yaml:"ipset6"`
	IPSetTTL int    `yaml:"ipset_ttl"`

	Redirector string `yaml:"redirector"`
}

func (g Group) IsSetGFWList() bool {
	return g.GFWListFile != "" || g.GFWListURL != ""
}

func (g Group) IsEmptyRule() bool {
	return len(g.Rules) == 0 && g.RulesFile == "" && !g.IsSetGFWList()
}

// RedirectorConf 重定向器配置
type RedirectorConf struct {
	Type      string   `yaml:"type"`
	Rules     []string `yaml:"rules"`
	RulesFile string   `yaml:"rules_file"`
	DstGroup  string   `yaml:"dst_group"`
}
