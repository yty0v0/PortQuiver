package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ServiceInfo 服务信息
type ServiceInfo struct {
	Host     string // 目标主机
	Port     int    // 端口号
	Protocol string // 传输层协议类型
	Service  string // 服务
	Banner   string // 服务Banner
}

// ServiceProbe 服务探测包
type ServiceProbe struct {
	Name      string
	Data      []byte
	SendFirst bool
	Match     []MatchRule
	Ports     []int
}

// MatchRule 匹配规则
type MatchRule struct {
	Pattern    []byte // 二进制模式匹配数据（用于二进制协议）
	PatternStr string // 字符串模式匹配规则（正则表达式，用于文本协议）
	Service    string // 匹配成功时标识的服务类型
	Proto      string // 传输层协议类型（tcp、udp）
	IsBinary   bool   // 标识是否使用二进制模式匹配
}

// ProtocolDetector 协议探测器
type ProtocolDetector struct {
	timeout   time.Duration
	userAgent string
	probes    []ServiceProbe
}

func NewProtocolDetector(timeout time.Duration) *ProtocolDetector {
	detector := &ProtocolDetector{
		timeout:   timeout,
		userAgent: "Mozilla/5.0 (compatible; SecurityScanner/1.0)", // 设置HTTP请求的用户代理标识
	}
	detector.initProbes()
	return detector
}

// 端口服务映射表 (基于IANA标准)
var portServiceMap = map[int]string{
	// 基础网络服务
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	67:    "dhcp-server",
	68:    "dhcp-client",
	69:    "tftp",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	123:   "ntp",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	514:   "syslog",
	587:   "smtps", // SMTP over SSL
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "ms-sql-s",
	1521:  "oracle",
	1723:  "pptp",
	1812:  "radius",
	1813:  "radius-acct",
	2049:  "nfs",
	2082:  "cpanel",
	2083:  "cpanel-ssl",
	2086:  "whm",
	2087:  "whm-ssl",
	2095:  "webmail",
	2096:  "webmail-ssl",
	2181:  "zookeeper",
	2375:  "docker",
	2376:  "docker-tls",
	3000:  "nodejs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5601:  "kibana",
	5672:  "amqp", // RabbitMQ
	5900:  "vnc",
	5938:  "teamviewer",
	5984:  "couchdb",
	6379:  "redis",
	6443:  "kubernetes",
	6667:  "irc",
	7001:  "weblogic",
	7002:  "weblogic-ssl",
	8000:  "http-alt",
	8005:  "tomcat",
	8008:  "http-alt",
	8009:  "ajp", // Apache JServ Protocol
	8080:  "http-proxy",
	8081:  "http-alt",
	8088:  "radan-http",
	8089:  "splunk",
	8090:  "http-alt",
	8091:  "couchbase",
	8140:  "puppet",
	8200:  "go-fastdfs",
	8443:  "https-alt",
	8686:  "sun-java-console",
	9000:  "cslistener",
	9001:  "tor-orport",
	9002:  "tor-dirport",
	9042:  "cassandra",
	9092:  "kafka",
	9200:  "elasticsearch",
	9300:  "elasticsearch-cluster",
	9418:  "git",
	9999:  "abyss",
	10000: "webmin",
	11211: "memcached",
	15672: "rabbitmq-management",
	27017: "mongodb",
	27018: "mongodb-shard",
	28017: "mongodb-http",
	50000: "db2",
	50070: "hadoop-namenode",

	// 游戏服务端口
	25565: "minecraft",
	27015: "steam",
	27500: "steam",

	// 网络安全设备
	//514:   "syslog",
	1514:  "syslog-tls",
	6514:  "syslog-tls",
	51413: "bittorrent",

	// 特定应用服务
	4369: "epmd",   // Erlang Port Mapper
	5353: "mdns",   // Multicast DNS
	5357: "wsdapi", // Web Services for Devices
	5431: "postgresql-alt",
	5985: "winrm", // Windows Remote Management
	5986: "winrm-ssl",
	6000: "x11",
	6001: "x11",
	6789: "campbell",
	6881: "bittorrent",
	6889: "bittorrent",
	6969: "bittorrent",
	7000: "afp", // Apple Filing Protocol
	7070: "realserver",
	7443: "nessus",
	7676: "imqbrokerd",
	8001: "http-alt",
	8010: "wingate",
	8074: "gadugadu",
	8083: "us-srv",
	8086: "influxdb",
	8099: "http-alt",
	8112: "privoxy",
	8123: "polipo",
	8181: "http-alt",
	8201: "transproxy",
	8222: "vmware-fdm",
	8243: "https-alt",
	8280: "http-alt",
	8281: "http-alt",
	8333: "bitcoin",
	8444: "https-alt",
	8500: "coldfusion",
	8530: "windows-remote",
	8531: "windows-remote",
	8649: "ganglia",
	8834: "nessus",
	8873: "dx-instrument",
	8880: "cddbp-alt",
	8888: "http-alt",
	8899: "ospf-lite",
	9009: "pichat",
	9010: "samba",
	9043: "tor-socks",
	9060: "webshield",
	9080: "glrpc",
	9090: "zeus-admin",
	9091: "xmltec-xmlmail",
	9100: "jetdirect",
	9119: "mxit",
	9150: "tor-socks",
	9151: "tor-control",
	9191: "sun-as-jpda",
	9290: "hp-gsg",
	9306: "sphinx",
	9415: "git",
	//9418:  "git",
	9443: "https-alt",
	9535: "mngsuite",
	9536: "laes-bf",
	9675: "spamassassin",
	9676: "spamassassin",
	9800: "webdav",
	9876: "sd",
	9898: "monkeycom",
	9988: "nfsd-keepalive",
	9990: "osm-appsrvr",
	//10000: "backupexec",
	10050: "zabbix-agent",
	10051: "zabbix-server",
	10113: "netiq-endpoint",
	10114: "netiq-qcheck",
	10115: "netiq-endpt",
	10116: "netiq-voipa",
	10243: "windows-rpc",
	10443: "cirrossp",
	10809: "nbd",
	11111: "vce",
	11214: "memcached",
	11215: "memcached",
	12000: "cce4x",
	12345: "netbus",
	13720: "bprd",
	13721: "bpdbm",
	13724: "vopied",
	13782: "bpcd",
	13783: "vopied",
	14534: "essbase",
	15118: "vpad",
	15205: "xpilot",
	15660: "bex-xr",
	15740: "ptp",
	16161: "sun-seaweb",
	16309: "etb4jan",
	16310: "pduncs",
	16311: "pdefmns",
	16992: "amt-soap-http",
	16993: "amt-soap-https",
	16994: "amt-redir-tcp",
	16995: "amt-redir-tls",
	17500: "dropbox",
	18080: "http-alt",
	18186: "opsec-ufp",
	18241: "checkpoint-rtm",
	18463: "ac-cluster",
	18769: "ique",
	18888: "apc-necmp",
	18999: "gv-us",
	19120: "j-link",
	19150: "gkrellm",
	19540: "sxuptp",
	19638: "enssim",
	20000: "dnp",
	20005: "openvpn-tcp",
	20547: "weblogin",
	21025: "bc-server",
	21590: "dynamic3d",
	21845: "webphone",
	22000: "snapenetio",
	22001: "optocontrol",
	22125: "dcap",
	22128: "gsidcap",
	22273: "wnn6",
	22305: "codemeter",
	22321: "wnn4",
	22343: "cis-secure",
	22347: "wibu-key",
	22350: "codemeter",
	22555: "vocaltec-admin",
	22763: "talikaserver",
	22800: "aws-brf",
	22951: "brf-gw",
	23000: "inovaport1",
	23001: "inovaport2",
	23002: "inovaport3",
	23003: "inovaport4",
	23004: "inovaport5",
	23005: "inovaport6",
	23053: "gntp",
	23294: "5afe-dir",
	23333: "elxmgmt",
	23424: "feitianrockey",
	23456: "aequus",
	23457: "aequus-alt",
	23546: "areaguard-neo",
	24000: "med-ltp",
	24001: "med-fsp-rx",
	24002: "med-fsp-tx",
	24003: "med-supp",
	24004: "med-ovw",
	24005: "med-ci",
	24006: "med-net-svc",
	24242: "filesphere",
	24249: "vista-4gl",
	24321: "ildp",
	24386: "intel_rci",
	24465: "tonidods",
	24554: "binkp",
	24577: "bilobit",
	24666: "sdtvwcam",
	24676: "canditv",
	24677: "flashfiler",
	24678: "proactivate",
	24680: "tcc-http",
	24754: "cslg",
	24922: "find",
	25000: "icl-twobase1",
	25001: "icl-twobase2",
	25002: "icl-twobase3",
	25003: "icl-twobase4",
	25004: "icl-twobase5",
	25005: "icl-twobase6",
	25006: "icl-twobase7",
	25007: "icl-twobase8",
	25008: "icl-twobase9",
	25009: "icl-twobase10",
	25560: "socalia",
	25604: "idtp",
	25793: "vocaltec-hos",
	25900: "tasp-net",
	25901: "niobserver",
	25902: "nilinkanalyst",
	25903: "niprobe",
	26000: "quake",
	26208: "wnn6-ds",
	26260: "ezproxy",
	26261: "ezmeeting",
	26262: "k3software-svr",
	26263: "k3software-cli",
	26486: "exoline-tcp",
	26487: "exoconfig",
	26489: "exonet",
	27000: "flexlm",
	27345: "imagepump",
	27442: "jesmsjc",
	27504: "kopek-httphead",
	27782: "ars-vista",
	27876: "astrolink",
	27999: "tw-auth-key",
	28000: "nxlmd",
	28001: "pqsp",
	28010: "gruber-cashreg",
	28080: "thor-engine",
	28200: "voxelstorm",
	28240: "siemensgsm",
	28589: "bosswave",
	29999: "bingbang",
	30000: "ndmps",
	30001: "pago-services1",
	30002: "pago-services2",
	30003: "amicon-fpsu-ra",
	30100: "rwp",
	30260: "kingdomsonline",
	30400: "gs-realtime",
	30999: "ovobs",
	31016: "ka-sddp",
	31020: "autotrac-acp",
	31337: "eldim",
	31415: "xqosd",
	31416: "xqosd",
	31457: "tetrinet",
	31620: "emc-xsw-dcache",
	31765: "gamesmith-port",
	31948: "iceedcp-tx",
	31949: "iceedcp-rx",
	32034: "iracinghelper",
	32249: "t1distproc60",
	32400: "plex",
	32768: "filenet-tms",
	32769: "filenet-rpc",
	32770: "filenet-nch",
	32771: "filenet-rmi",
	32772: "filenet-pa",
	32773: "filenet-cm",
	32774: "filenet-re",
	32775: "filenet-pch",
	32776: "filenet-peior",
	32777: "filenet-obrok",
	32801: "mlsn",
	32811: "retp",
	32896: "idmgratm",
	33060: "mysqlx",
	33123: "aurora-balaena",
	33331: "diamondport",
	33334: "speedtrace",
	33434: "traceroute",
	33656: "snip-slave",
	34249: "turbonote-2",
	34378: "p-net-remote",
	34567: "dhanalakshmi",
	34962: "profinet-rt",
	34963: "profinet-rtm",
	34964: "profinet-cm",
	34980: "ethercat",
	36865: "kastenxpipe",
	37475: "neckar",
	37601: "eftp",
	38412: "ng-control",
	39681: "turbonote-1",
	40000: "safetynetp",
	40404: "sptx",
	40841: "cscp",
	40842: "csccredir",
	40843: "csccfirewall",
	41121: "tentacle",
	41794: "crestron-cip",
	41795: "crestron-ctp",
	42508: "candp",
	42509: "candrp",
	42510: "caerpc",
	44334: "tinyfw",
	44444: "cognex-dataman",
	44553: "rbr-debug",
	44818: "EtherNet/IP-2",
	45000: "asmp-mon",
	45045: "synctest",
	45514: "cloudcheck",
	45678: "eba",
	45824: "dai-shell",
	45966: "ssr-servermgr",
	46998: "spremotetablet",
	46999: "mediabox",
	47000: "mbus",
	47557: "dbbrowse",
	47624: "directplaysrvr",
	47806: "ap",
	47808: "bacnet",
	48000: "nimcontroller",
	48001: "nimspooler",
	48002: "nimhub",
	48003: "nimgtw",
	48004: "nimbusdb",
	48005: "nimbusdbctrl",
	48128: "isnetserv",
	48129: "blp5",
	48556: "com-bardac-dw",
	48619: "iqobject",
	48653: "robotraconteur",
	49000: "matahari",
	//50000: "ibm-db2",
	50001: "infimas",
	50002: "pro-activate",
	50003: "ita-agent",
	50006: "rbt-wanopt",
	50090: "iiimsf",
	50500: "ita-manager",
	50636: "intecom-ps1",
	50800: "gbmt-stars",
	51515: "pcp",
	51678: "scte104",
	51717: "pcoip-mgmt",
	51999: "eforward",
	52000: "irisa",
	52345: "proofd",
	54127: "sns-agent",
	54321: "bo2k",
	55050: "supervisord",
	55553: "pcanywherestat",
	55555: "rplay",
	55600: "isqlplus",
	56737: "dpm",
	57294: "proshutdown",
	57797: "dali-port",
	58000: "vnc-http",
	58001: "vnc-http-1",
	58002: "vnc-http-2",
	58003: "vnc-http-3",
	60000: "deep",
	60001: "mgetty",
	60020: "dectalk",
	61439: "netprowler-sensor",
	61440: "netprowler-manager",
	61441: "netprowler-manager2",
	62078: "iphone-sync",
	62514: "tl1-raw-ssl",
	6346:  "gnutella",
	6347:  "gnutella2",
	65000: "distributed-net",
	65301: "pcanywhere",
}

// 初始化探测包
func (pd *ProtocolDetector) initProbes() {
	pd.probes = []ServiceProbe{
		// SSH探测
		{
			Name:      "SSHProbe",
			Data:      []byte("SSH-2.0-Client\r\n"),
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `^SSH-([0-9.]+)-`, Service: "ssh", Proto: "tcp"},
				{PatternStr: `OpenSSH[_-]([0-9.]+)`, Service: "ssh", Proto: "tcp"},
			},
		},

		// SMTP探测
		{
			Name:      "SMTPBanner",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^220\s`, Service: "smtp", Proto: "tcp"},
				{PatternStr: `^220-`, Service: "smtp", Proto: "tcp"},
				{PatternStr: `ESMTP (Postfix|Sendmail|Exim)`, Service: "smtp", Proto: "tcp"},
			},
		},
		{
			Name:      "SMTPHelo",
			Data:      []byte("HELO scanner\r\n"),
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `^250\s`, Service: "smtp", Proto: "tcp"},
			},
		},

		// POP3探测
		{
			Name:      "POP3Banner",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^\+\s?OK`, Service: "pop3", Proto: "tcp"},
			},
		},
		{
			Name:      "POP3Command",
			Data:      []byte("USER test\r\n"),
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `^\+OK`, Service: "pop3", Proto: "tcp"},
				{PatternStr: `^-ERR`, Service: "pop3", Proto: "tcp"},
			},
		},

		// FTP探测
		{
			Name:      "FTPBanner",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^220\s`, Service: "ftp", Proto: "tcp"},
				{PatternStr: `FTP server.*ready`, Service: "ftp", Proto: "tcp"},
			},
		},

		// RPCBind探测
		{
			Name: "RPCBindProbe",
			Data: []byte{
				0x80, 0x00, 0x00, 0x28, 0x79, 0x18, 0xae, 0x7c,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
				0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			SendFirst: true,
			Match: []MatchRule{
				{Pattern: []byte{0x80, 0x00, 0x00, 0x28}, Service: "rpcbind", Proto: "tcp", IsBinary: true},
			},
		},

		// SMB探测
		{
			Name: "SMBProbe",
			Data: []byte{
				0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00,
				0x00, 0x00, 0x00, 0x18, 0x53, 0xC8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02,
				0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4E, 0x52, 0x4B,
				0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31,
				0x2E, 0x30, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E,
				0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
				0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72,
				0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2E,
				0x31, 0x61, 0x00, 0x02, 0x4C, 0x4C, 0x31, 0x2E, 0x32, 0x58,
				0x30, 0x30, 0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41,
				0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C,
				0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
			},
			SendFirst: true,
			Match: []MatchRule{
				{Pattern: []byte{0xFF, 0x53, 0x4D, 0x42}, Service: "microsoft-ds", Proto: "tcp", IsBinary: true},
			},
		},

		// 增强的 MySQL 探测
		{
			Name:      "MySQLBanner",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `\x00\x00\x00\x0a([0-9.]+)-MariaDB`, Service: "mysql", Proto: "tcp"},
				{PatternStr: `\x00\x00\x00\x0a([0-9.]+)`, Service: "mysql", Proto: "tcp"},
				{PatternStr: `mysql_native_password`, Service: "mysql", Proto: "tcp"},
			},
		},
		{
			Name:      "MySQLHandshake",
			Data:      []byte{}, // 不发送数据，直接读取握手包
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^.\x00\x00\x00\x0a([0-9.]+)`, Service: "mysql", Proto: "tcp", IsBinary: false},
				{Pattern: []byte{0x00, 0x00, 0x00, 0x0a}, Service: "mysql", Proto: "tcp", IsBinary: true},
			},
		},
		{
			Name: "MySQLAuth",
			Data: []byte{
				0x85, 0xa6, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01,
				0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x72, 0x6f, 0x6f, 0x74, 0x00, 0x00,
			},
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `\x00\x00\x01\xff`, Service: "mysql", Proto: "tcp"},
				{PatternStr: `Host '.*' is not allowed`, Service: "mysql", Proto: "tcp"},
				{PatternStr: `Access denied for user`, Service: "mysql", Proto: "tcp"},
			},
		},

		{
			Name:      "MySQLVersion",
			Data:      []byte{0x0a, 0x00, 0x00, 0x00, 0x0a, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x40, 0x40, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x4c, 0x49, 0x4d, 0x49, 0x54, 0x20, 0x31},
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `mysql`, Service: "mysql", Proto: "tcp", IsBinary: false},
				{PatternStr: `MariaDB`, Service: "mysql", Proto: "tcp", IsBinary: false},
			},
		},

		// PostgreSQL探测
		{
			Name:      "PostgreSQLProbe",
			Data:      []byte{},
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^E\s+.*FATAL:`, Service: "postgresql", Proto: "tcp"},
				{PatternStr: `PostgreSQL`, Service: "postgresql", Proto: "tcp"},
			},
		},

		// Redis探测
		{
			Name:      "RedisProbe",
			Data:      []byte("*1\r\n$4\r\nPING\r\n"),
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `^-ERR`, Service: "redis", Proto: "tcp"},
				{PatternStr: `^\+PONG`, Service: "redis", Proto: "tcp"},
				{PatternStr: `^-NOAUTH`, Service: "redis", Proto: "tcp"},
			},
		},

		// Telnet探测
		{
			Name:      "TelnetProbe",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^.*login:`, Service: "telnet", Proto: "tcp"},
				{PatternStr: `^.*Password:`, Service: "telnet", Proto: "tcp"},
			},
		},

		// DNS探测
		{
			Name: "DNSProbe",
			Data: []byte{
				0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
				0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			SendFirst: true,
			Match: []MatchRule{
				{Pattern: []byte{0x12, 0x34}, Service: "dns", Proto: "tcp", IsBinary: true},
			},
		},

		// Memcached探测
		{
			Name:      "MemcachedProbe",
			Data:      []byte("version\r\n"),
			SendFirst: true,
			Match: []MatchRule{
				{PatternStr: `^VERSION`, Service: "memcached", Proto: "tcp"},
				{PatternStr: `^ERROR`, Service: "memcached", Proto: "tcp"},
			},
		},

		// RDP探测
		{
			Name: "RDPProbe",
			Data: []byte{
				0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
			},
			SendFirst: true,
			Match: []MatchRule{
				{Pattern: []byte{0x03, 0x00, 0x00, 0x13}, Service: "rdp", Proto: "tcp", IsBinary: true},
			},
		},

		// IMAP探测
		{
			Name:      "IMAPBanner",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^\* OK`, Service: "imap", Proto: "tcp"},
				{PatternStr: `IMAP4`, Service: "imap", Proto: "tcp"},
			},
		},

		// 通用Banner抓取 (放在最后作为兜底)
		{
			Name:      "GenericBanner",
			Data:      []byte(""),
			SendFirst: false,
			Match: []MatchRule{
				{PatternStr: `^SSH-([0-9.]+)-`, Service: "ssh", Proto: "tcp"},
				{PatternStr: `^220\s`, Service: "smtp", Proto: "tcp"},
				{PatternStr: `^\+\s?OK`, Service: "pop3", Proto: "tcp"},
				{PatternStr: `^HTTP/1\.[01]\s`, Service: "http", Proto: "tcp"},
				{PatternStr: `\bMicrosoft\b`, Service: "netbios-ssn", Proto: "tcp"},
				{PatternStr: `\bSamba\b`, Service: "microsoft-ds", Proto: "tcp"},
				// Web 服务器识别
				{PatternStr: `nginx/([0-9.]+)`, Service: "nginx", Proto: "tcp"},
				{PatternStr: `Apache/([0-9.]+)`, Service: "apache", Proto: "tcp"},
				{PatternStr: `Microsoft-IIS/([0-9.]+)`, Service: "microsoft-iis", Proto: "tcp"},
				{PatternStr: `IIS/([0-9.]+)`, Service: "microsoft-iis", Proto: "tcp"},
				{PatternStr: `Tomcat/([0-9.]+)`, Service: "tomcat", Proto: "tcp"},
				// 数据库识别
				{PatternStr: `MySQL`, Service: "mysql", Proto: "tcp"},
				{PatternStr: `PostgreSQL`, Service: "postgresql", Proto: "tcp"},
				{PatternStr: `Redis`, Service: "redis", Proto: "tcp"},
				{PatternStr: `MongoDB`, Service: "mongodb", Proto: "tcp"},
				// 其他常见服务
				{PatternStr: `FTP server`, Service: "ftp", Proto: "tcp"},
				{PatternStr: `IMAP`, Service: "imap", Proto: "tcp"},
				{PatternStr: `POP3`, Service: "pop3", Proto: "tcp"},
				{PatternStr: `Telnet`, Service: "telnet", Proto: "tcp"},
				{PatternStr: `memcached`, Service: "memcached", Proto: "tcp"},
				{PatternStr: `ZooKeeper`, Service: "zookeeper", Proto: "tcp"},
				{PatternStr: `RabbitMQ`, Service: "amqp", Proto: "tcp"},
				{PatternStr: `Elasticsearch`, Service: "elasticsearch", Proto: "tcp"},
				{PatternStr: `Kafka`, Service: "kafka", Proto: "tcp"},
			},
		},
	}
}

// 智能端口预判探测
func (pd *ProtocolDetector) DetectProtocol(host string, port int) *ServiceInfo {
	// 设置智能探测最大时间（比如总超时的1/3）
	maxSmartDetectTime := pd.timeout / 3
	deadline := time.Now().Add(maxSmartDetectTime)

	quickProbes := pd.getQuickProbesForPort(port) //获取常见端口对应的识别数据名称

	// 首先尝试自定义规则（最高优先级）
	customMgr := GetCustomRulesManager()
	if customMgr.IsLoaded() {
		customProbes := customMgr.GetCustomProbesForPort(port)
		for _, probe := range customProbes {
			// 检查是否超时
			if time.Now().After(deadline) {
				break
			}

			if result := pd.executeProbeWithTimeout(host, port, probe); result != nil {
				result.Service = result.Service + "(自定义识别结果)" // 添加自定义标识
				return result
			}
		}
	}

	// 执行快速探测
	for _, probeName := range quickProbes {
		// 检查是否超时
		if time.Now().After(deadline) {
			break
		}

		for i := range pd.probes {
			//在probes切片中找和刚才获取到的识别数据名称匹配的名称，找到以后使用这个识别规则进行识别
			if pd.probes[i].Name == probeName {
				if result := pd.executeProbeWithTimeout(host, port, pd.probes[i]); result != nil {
					//fmt.Println(port)
					return result
				}
				break
			}
		}
	}

	// 智能探测失败或超时，回退到完整探测
	return pd.fullProtocolDetection(host, port)
}

// 带超时的探测执行
func (pd *ProtocolDetector) executeProbeWithTimeout(host string, port int, probe ServiceProbe) *ServiceInfo {
	if len(probe.Match) > 0 && probe.Match[0].Proto == "udp" {
		//进行udp协议探测
		return pd.executeUDPProbe(host, port, probe)
	} else {
		//进行tcp协议探测
		return pd.executeTCPProbe(host, port, probe)
	}
}

// 根据端口获取快速探测列表
func (pd *ProtocolDetector) getQuickProbesForPort(port int) []string {
	switch port {
	case 80, 8080, 8000, 8081, 8008, 8088, 8090, 8888:
		return []string{"GenericBanner"} // HTTP会在detectHTTP中处理
	case 443, 8443:
		return []string{"GenericBanner"} // HTTPS会在detectHTTPS中处理
	case 22:
		return []string{"SSHProbe", "GenericBanner"}
	case 21:
		return []string{"FTPBanner", "GenericBanner"}
	case 23:
		return []string{"TelnetProbe", "GenericBanner"}
	case 25, 587:
		return []string{"SMTPBanner", "SMTPHelo", "GenericBanner"}
	case 53:
		return []string{"DNSProbe", "GenericBanner"}
	case 110, 995:
		return []string{"POP3Banner", "POP3Command", "GenericBanner"}
	case 143, 993:
		return []string{"IMAPBanner", "GenericBanner"}
	case 161, 162:
		return []string{"GenericBanner"} // SNMP
	case 389, 636:
		return []string{"GenericBanner"} // LDAP
	case 445:
		return []string{"SMBProbe", "GenericBanner"}
	case 3306:
		return []string{"MySQLAuthError", "GenericBanner"}
	case 3389:
		return []string{"RDPProbe", "GenericBanner"}
	case 5432:
		return []string{"PostgreSQLProbe", "GenericBanner"}
	case 6379:
		return []string{"RedisProbe", "GenericBanner"}
	case 27017:
		return []string{"GenericBanner"}
	case 11211:
		return []string{"MemcachedProbe", "GenericBanner"}
	default:
		return []string{"GenericBanner"}
	}
}

// 完整的协议探测（原逻辑，作为回退）
func (pd *ProtocolDetector) fullProtocolDetection(host string, port int) *ServiceInfo {
	// 1. 尝试HTTP/HTTPS（最常用）
	if result := pd.detectHTTP(host, port); result != nil {
		return result
	}

	// 2. 执行所有协议探测
	for i := range pd.probes {
		// 跳过已经快速探测过的协议
		if pd.isProbeInQuickList(pd.probes[i].Name, port) {
			continue
		}

		var result *ServiceInfo
		if len(pd.probes[i].Match) > 0 && pd.probes[i].Match[0].Proto == "udp" {
			result = pd.executeUDPProbe(host, port, pd.probes[i])
		} else {
			result = pd.executeTCPProbe(host, port, pd.probes[i])
		}
		if result != nil {
			return result
		}
	}

	// 3. 端口推断
	return pd.inferByPortWithBanner(host, port)
}

// 检查探测是否在快速列表中
func (pd *ProtocolDetector) isProbeInQuickList(probeName string, port int) bool {
	quickProbes := pd.getQuickProbesForPort(port)
	for _, name := range quickProbes {
		if name == probeName {
			return true
		}
	}
	return false
}

// 端口推断
func (pd *ProtocolDetector) inferByPort(port int) string {
	if service, exists := portServiceMap[port]; exists {
		return service
	}
	return "unknown"
}

// 端口推断带banner抓取
func (pd *ProtocolDetector) inferByPortWithBanner(host string, port int) *ServiceInfo {
	service := pd.inferByPort(port)

	return &ServiceInfo{
		Host:    host,
		Port:    port,
		Service: service,
	}
}

// 执行TCP探测
func (pd *ProtocolDetector) executeTCPProbe(host string, port int, probe ServiceProbe) *ServiceInfo {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 1*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	var response []byte

	//设置下面conn所有操作的总超时
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	if probe.SendFirst {
		// 先发送数据再读取响应
		if len(probe.Data) > 0 {
			conn.Write(probe.Data)
		}

		//这里设置for循环持续监听响应，是由于响应数据可能分为多段发送，设置三次读取即可，不用设置总超时的读取
		for i := 0; i < 3; i++ {
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil {
				continue
			}
			if n > 0 {
				response = append(response, buffer[:n]...)
			}
		}

	} else {
		// 先读取banner，不发送数据
		//这里设置for循环持续监听响应，是由于响应数据可能分为多段发送，设置三次读取即可，不用设置总超时的读取
		for i := 0; i < 3; i++ {
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil && n == 0 {
				return nil
			}
			if n > 0 {
				response = append(response, buffer[:n]...)
			}
		}
	}

	return pd.matchResponse(host, port, response, probe) //在调用的方法里对数据是否为空已经做了处理，此处忽略。
}

// 执行UDP探测
func (pd *ProtocolDetector) executeUDPProbe(host string, port int, probe ServiceProbe) *ServiceInfo {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), 1*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	var response []byte

	//设置下面conn所有操作的总超时
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	if probe.SendFirst {
		// 先发送数据再读取响应
		if len(probe.Data) > 0 {
			_, err = conn.Write(probe.Data)
			if err != nil {
				return nil
			}
		}

		//这里设置for循环持续监听响应，是由于响应数据可能分为多段发送，设置三次读取即可，不用设置总超时的读取
		for i := 0; i < 3; i++ {
			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil {
				continue
			}
			if n > 0 {
				response = append(response, buffer[:n]...)
			}
		}

	} else {
		// UDP协议通常需要先发送数据才能获取响应，所以不发送数据直接返回nil
		return nil
	}

	return pd.matchResponse(host, port, response, probe) //在调用的方法里对数据是否为空已经做了处理，此处忽略。
}

// 匹配响应数据
func (pd *ProtocolDetector) matchResponse(host string, port int, response []byte, probe ServiceProbe) *ServiceInfo {
	if len(response) == 0 {
		return nil
	}

	//遍历识别规则
	for _, rule := range probe.Match {
		var matched bool //判断是否匹配成功

		if rule.IsBinary { //判断是否为二进制识别规则
			matched = bytes.Contains(response, rule.Pattern) //查看响应数据是否包含这个二进制数据
		} else { //正则匹配的识别规则
			responseStr := string(response)
			re := regexp.MustCompile(rule.PatternStr) //把这串字符规则转换成计算机能快速执行的格式
			if re.MatchString(responseStr) {          //用编译好的规则去检查文字，判断是否匹配成功
				matched = true
			}
		}

		if matched {
			bannerStr := strings.TrimSpace(string(response)) //去除文字开头和结尾的空白字符

			//如果返回数据过长就去掉一部分
			if len(bannerStr) > 200 {
				bannerStr = bannerStr[:200] + "..."
			}

			return &ServiceInfo{
				Host:     host,
				Port:     port,
				Protocol: rule.Proto,
				Service:  rule.Service,
				Banner:   bannerStr,
			}
		}
	}

	return nil
}

// HTTP探测
func (pd *ProtocolDetector) detectHTTP(host string, port int) *ServiceInfo {
	client := &http.Client{
		Timeout: pd.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { // 遇到3xx状态码立即停止，返回原始响应
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("http://%s:%d/", host, port)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", pd.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return pd.detectHTTPS(host, port)
	}
	defer resp.Body.Close()

	service := "http"
	if resp.TLS != nil {
		service = "https"
	}

	info := &ServiceInfo{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		Service:  service,
	}

	server := resp.Header.Get("Server")
	if server != "" {
		info.Banner = fmt.Sprintf("HTTP/%d Server: %s", resp.StatusCode, server)
		info.Service = server
	} else {
		info.Banner = fmt.Sprintf("HTTP/%d", resp.StatusCode)
	}

	return info
}

// HTTPS探测
func (pd *ProtocolDetector) detectHTTPS(host string, port int) *ServiceInfo {
	client := &http.Client{
		Timeout: pd.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	url := fmt.Sprintf("https://%s:%d/", host, port)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", pd.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	info := &ServiceInfo{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		Service:  "https",
	}

	server := resp.Header.Get("Server")
	if server != "" {
		info.Banner = fmt.Sprintf("HTTPS/%d Server: %s", resp.StatusCode, server)
		info.Service = server
	} else {
		info.Banner = fmt.Sprintf("HTTPS/%d", resp.StatusCode)
	}

	return info
}

// 批量探测
func (pd *ProtocolDetector) BatchDetect(host string, ports []int) []*ServiceInfo {
	var results []*ServiceInfo //存储所有指纹识别结果
	var mu sync.Mutex
	var wg sync.WaitGroup

	//传入端口为空的情况
	if len(ports) == 0 {
		return nil
	}

	semaphore := make(chan struct{}, 20)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := pd.DetectProtocol(host, p) //返回指纹识别结果
			if result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(port)

		// 自定义规则之间添加小延迟
		time.Sleep(500 * time.Millisecond)
	}

	wg.Wait()
	return results
}
