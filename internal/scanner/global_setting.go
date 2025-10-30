package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var Wg sync.WaitGroup
var Mu sync.Mutex

var Services = map[int]string{
	// 基础网络服务
	20:  "FTP Data",
	21:  "FTP Control",
	22:  "SSH",
	23:  "Telnet",
	25:  "SMTP",
	53:  "DNS",
	67:  "DHCP Server",
	68:  "DHCP Client",
	69:  "TFTP",
	80:  "HTTP",
	110: "POP3",
	111: "RPC/Portmap",
	123: "NTP",
	135: "MSRPC",
	137: "NetBIOS Name Service",
	138: "NetBIOS Datagram Service",
	139: "NetBIOS Session Service",
	143: "IMAP",
	161: "SNMP",
	162: "SNMP Trap",
	389: "LDAP",
	443: "HTTPS",
	445: "SMB",
	514: "Syslog",
	520: "RIP",
	587: "SMTP (Submission)",
	993: "IMAPS",
	995: "POP3S",

	// 数据库服务
	1433:  "MSSQL",
	1434:  "MSSQL Resolution",
	1521:  "Oracle",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	27017: "MongoDB",
	6379:  "Redis",

	// 远程访问
	3389: "RDP",
	5900: "VNC",
	5985: "WinRM HTTP",
	5986: "WinRM HTTPS",

	// 网络设备管理
	//22:    "SSH",
	//23:    "Telnet",
	//161:   "SNMP",
	//443:   "HTTPS (Web管理)",
	830: "NETCONF",

	// 应用服务
	5060: "SIP",
	5061: "SIPS",
	5222: "XMPP Client",
	5269: "XMPP Server",
	8000: "HTTP Alt",
	8080: "HTTP Proxy",
	8443: "HTTPS Alt",
	9000: "PHP-FPM",

	// 多媒体和游戏
	1935: "RTMP",
	3478: "STUN/TURN",
	//5060:  "SIP",
	5353:  "mDNS",
	1900:  "SSDP",
	27015: "Steam",
	19132: "Minecraft",
	25565: "Minecraft (Java)",

	// 消息队列和缓存
	5672:  "AMQP",
	61613: "STOMP",
	11211: "Memcached",

	// 监控和管理
	3000: "Grafana",
	9090: "Prometheus",
	9100: "Node Exporter",
	9200: "Elasticsearch",
	9300: "Elasticsearch Cluster",
	5601: "Kibana",

	// 容器和编排
	2375:  "Docker",
	2376:  "Docker TLS",
	2379:  "etcd",
	2380:  "etcd Peer",
	6443:  "Kubernetes API",
	10250: "Kubelet",
	10255: "Kubelet Read-only",
}

// getService 获取端口对应的服务名称
func GetService(port int) string {
	if service, exists := Services[port]; exists {
		return service
	}
	return "unknown"
}

// 辅助函数，获取ipv4地址
func SelectIPv4(addrs []net.IP) (net.IP, error) {
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, fmt.Errorf("未找到IPv4地址")
}

// 根据目标IP获取本地IP和端口
func GetlocalIPPort(dstip string) (net.IP, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip+":54321")
	if err != nil {
		return nil, 0, err
	}

	con, err := net.DialUDP("udp", nil, serverAddr)
	if err == nil {
		udpaddr, ok := con.LocalAddr().(*net.UDPAddr)
		if ok {
			return udpaddr.IP, udpaddr.Port, nil
		}
	}
	defer con.Close()
	return nil, -1, err
}

// generateRandomSeq 生成随机序列号
func GenerateRandomSeq() uint32 {
	return uint32(time.Now().UnixNano())
}

// 获取随机源端口
func GenerateRandomPort() int {
	return 40000 + time.Now().Nanosecond()%1000
}

// 处理ip地址，使主机位可以进行遍历（示例：传入host=192.168.5.1,j=6，经过这个函数可以把host改为192.168.5.6）
func Ip_handle1(host string, j int) string {
	arr := strings.Split(host, ".") //根据'.'将字符串分割成数组
	arr[3] = fmt.Sprintf("%d", j)   //把int类型转为string类型再赋值
	arr1 := strings.Join(arr, ".")  //用'.'重新连接数字每一项
	return arr1
}

// 处理ip地址，处理范围输入的情况，（示例：传入192.168.5.1-100，经过这个函数可以提取出start=1,end=100）
func Ip_handle2(host string) (string, string) {
	var start, end string
	arr := strings.Split(host, "-")

	//判断是范围输入还是单个ip输入
	if len(arr) != 2 { //单个ip输入的情况
		arr1 := strings.Split(arr[0], ".")
		start = arr1[3]
		end = start //初始范围等于结束范围
	} else { //范围ip输入的情况
		end = arr[len(arr)-1]
		arr1 := strings.Split(arr[0], ".")
		start = arr1[3]
	}
	return start, end
}
