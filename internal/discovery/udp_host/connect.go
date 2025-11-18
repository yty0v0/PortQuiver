package udp_host

import (
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/discovery/utils"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

type UDPResult struct {
	IP       string
	HostInfo string
	State    string
	Reason   string
}

var results_udp_survival []UDPResult //存储所有存活主机

func Udp_connect(ipaddres []string, rate int) {

	//如果rate是默认值，则设置为并100（并发100的结果更准确）
	if rate == 300 {
		rate = 100
	}
	sem := make(chan struct{}, rate) // 减少并发数避免竞争

	fmt.Println("开始 UDP 存活扫描...")
	start := time.Now()

	// 为每个goroutine创建独立的ICMP监听器
	for _, ipaddr := range ipaddres {
		// 为每个IP尝试多个端口
		keyPorts := []int{53, 123, 137, 138, 161, 67, 68, 69, 111, 135, 445, 514, 520, 1900}
		for _, port := range keyPorts {
			scanner.Wg.Add(1)
			go func(ip string, port int) {
				sem <- struct{}{}
				defer scanner.Wg.Done()
				defer func() { <-sem }()

				state, reason := udpScanWithICMP(ip, port)
				if state == "up" {

					result := UDPResult{
						IP:       ip,
						HostInfo: "",
						State:    state,
						Reason:   reason,
					}
					scanner.Mu.Lock()
					// 检查是否已经记录过这个IP，因为是扫描一个ip的多个端口
					found := false
					for _, r := range results_udp_survival {
						if r.IP == ip {
							found = true
							break
						}
					}
					if !found {
						results_udp_survival = append(results_udp_survival, result)
					}
					scanner.Mu.Unlock()
				}
			}(ipaddr, port)
		}
	}
	scanner.Wg.Wait()

	//获取MAC地址
	var targetIps []string
	for _, result := range results_udp_survival {
		targetIps = append(targetIps, result.IP)
	}
	MacResult := utils.GetMac(targetIps)

	//获取主机信息
	var datas []utils.HostInfoResult //HostInfoResult在hostinfo代码里已经定义成全局变量
	for _, result := range results_udp_survival {
		data := utils.HostInfoResult{
			IP:  result.IP,
			MAC: MacResult[result.IP],
		}
		datas = append(datas, data)
	}
	collector := utils.NewHostInfo() //这一行确实已经调用了函数
	InfoResult := collector.GetHostInfoBatch(datas)

	// 输出结果
	fmt.Println("\n存活主机列表：")
	//fmt.Println("IP地址\t\tMAC地址\t\t\t主机信息\t\t状态\t\t原因")
	results := make(map[string]int)
	for _, v := range results_udp_survival {
		if results[v.IP] == 0 {
			//fmt.Printf("%s\t%s\t%s\t%s\t%s\n", v.IP, MacResult[v.IP], v.HostInfo, v.State, v.Reason)

			fmt.Printf("IP地址:%s\n", v.IP)
			fmt.Printf("MAC地址:%s\n", MacResult[v.IP])
			fmt.Printf("主机信息:%s\n", InfoResult[v.IP])
			fmt.Printf("主机状态:%s\n", v.State)
			fmt.Printf("存活原因:%s\n", v.Reason)
			fmt.Println()
		}
		results[v.IP]++
	}
	fmt.Printf("共发现 %d 台存活主机\n", len(results_udp_survival))
	fmt.Printf("运行时间: %v\n", time.Since(start))
}

// UDP扫描并监听ICMP响应 - 每个goroutine独立的连接
func udpScanWithICMP(target string, port int) (string, string) {
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return "down", "invalid_ip"
	}

	// 首先创建独立的ICMP监听器
	icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return "down", "icmp_listen_failed"
	}
	defer icmpConn.Close()

	// 创建UDP连接
	address := fmt.Sprintf("%s:%d", target, port)
	udpConn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return "down", "udp_conn_failed"
	}
	defer udpConn.Close()

	// 通过UDP连接发送探测数据（不同服务可能需要不同的数据）
	probeData := getProbeData(port)
	_, err = udpConn.Write(probeData)
	if err != nil {
		return "down", "udp_send_failed"
	}

	//设置总超时
	deadline := time.Now().Add(2 * time.Second)

	for {
		if time.Now().After(deadline) {
			return "down", "timeout"
		}

		// 设置icmp和udp响应的读取超时
		icmpConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		udpConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))

		// 先尝试接收UDP响应（端口开放）
		response := make([]byte, 1024)
		n, err := udpConn.Read(response)
		if err == nil && n > 0 {
			return "up", fmt.Sprintf("udp_open_%d", port)
		}

		//然后尝试接受收icmp响应
		buffer := make([]byte, 1500)
		n, addr, err := icmpConn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 短超时，继续等待
			}
			return "down", "icmp_read_failed"
		}

		// 检查是否来自目标IP
		remoteIP, ok := addr.(*net.IPAddr)
		if !ok || !remoteIP.IP.Equal(targetIP) {
			continue
		}

		// 解析ICMP包
		if n >= 8 {
			// 确保收到完整的ICMP头部（8字节)
			// ICMP Type 3 = Destination Unreachable
			// Code 3 = Port Unreachable
			if buffer[0] == 3 && buffer[1] == 3 {
				return "up", fmt.Sprintf("icmp_port_unreachable_%d", port)
			}
			// 其他Destination Unreachable对应的错误也说明主机存活
			if buffer[0] == 3 {
				return "up", "icmp_dest_unreachable"
			}
			//Type = 11: Time Exceeded
			//含义: TTL超时，证明数据包在网络中传输，有路由器在响应
			if buffer[0] == 11 {
				return "up", "icmp_time_exceeded"
			}
		}
	}

	return "down", "no_response"
}

// 根据端口返回不同的探测数据
func getProbeData(port int) []byte {
	switch port {
	case 53: // DNS - 查询根域名
		return []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	case 161: // SNMP - 有效的get-request
		return []byte{0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63}

	case 123: // NTP - 模式3(客户端)请求
		return []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	case 137, 138: // NetBIOS - 名称查询
		return []byte{0x80, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01}

	case 67, 68: // DHCP - 发现包
		return []byte{0x01, 0x01, 0x06, 0x00}

	case 69: // TFTP - 读请求
		return []byte{0x00, 0x01, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00}

	case 111: // RPC - portmap查询
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xA0}

	case 135: // MSRPC - 端点映射
		return []byte{0x05, 0x00, 0x0B, 0x03, 0x10, 0x00, 0x00, 0x00}

	case 445: // SMB - 协商协议
		return []byte{0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8}

	case 514: // Syslog - 测试消息
		return []byte("<0>Test Syslog Message")

	case 520: // RIP - 请求
		return []byte{0x01, 0x01, 0x00, 0x00}

	case 1900: // SSDP - 发现请求
		return []byte("M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n")

	default:
		// 对于未知端口，发送更有意义的数据
		return []byte("PING")
	}
}
