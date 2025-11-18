package udp_port

import (
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scan/utils"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

// UDP扫描结果结构
type UDPResult struct {
	Port    int
	State   string // "open", "closed", "open|filtered", "error"
	Service string
}

// UDP端口扫描操作
func Udp_connect(ipaddress string, ports []int, rate int) {
	results := make(map[int]UDPResult)
	sem := make(chan struct{}, rate) // 并发控制

	fmt.Printf("开始UDP扫描 %s...\n", ipaddress)
	start := time.Now()

	for _, port := range ports {
		scanner.Wg.Add(1)
		go func(p int) {
			sem <- struct{}{}        // 获取信号量
			defer func() { <-sem }() // 释放信号量
			defer scanner.Wg.Done()

			result := scanUDPPort(ipaddress, p, 3*time.Second)

			scanner.Mu.Lock()
			results[p] = result
			scanner.Mu.Unlock()

		}(port)
	}
	scanner.Wg.Wait()

	openPorts := 0
	openfilteredPorts := 0
	errorPorts := 0

	//获取端口服务
	var data_port []int
	for _, result := range results {
		if result.State == "open" {
			data_port = append(data_port, result.Port)
			openPorts++
		}
		if result.State == "open|filtered" {
			openfilteredPorts++
		}
		if result.State == "error" {
			errorPorts++
		}
	}
	detector := utils.NewProtocolDetector(3 * time.Second)
	results_server := detector.BatchDetect(ipaddress, data_port)

	fmt.Println("\n扫描结果:")
	fmt.Println("端口\t状态\t服务")

	for _, v := range results_server {
		if results[v.Port].State == "open" {
			fmt.Printf("%d\topen\t%s", v.Port, v.Service)
		}
		fmt.Println()
	}

	fmt.Println()
	if openPorts == 0 && openfilteredPorts == 0 {
		fmt.Println("没有发现开放的UDP端口")
	} else if openPorts != 0 {
		fmt.Printf("共发现 %d 个开放的UDP端口，%d 个端口可能开放或被过滤，%d 个端口出现错误\n", openPorts, openfilteredPorts, errorPorts)
	} else {
		fmt.Printf(" 扫描的 %d 个端口可能开放或被过滤，%d 个端口出现错误\n", openfilteredPorts, errorPorts)
		fmt.Println("结果输出忽略")
	}

	usetime := time.Since(start)
	fmt.Printf("扫描完成，耗时: %v\n", usetime)
}

// UDP端口扫描函数
func scanUDPPort(ip string, port int, timeout time.Duration) UDPResult {
	//创建一个结构体实例
	result := UDPResult{
		Port:    port,
		Service: "",
		State:   "open|filtered", // 默认状态
	}

	// 构造目标地址
	target := fmt.Sprintf("%s:%d", ip, port)

	// 创建UDP连接
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		result.State = "error"
		return result
	}
	defer conn.Close()

	// 发送探测数据
	probeData := getProbeData(port)
	_, err = conn.Write(probeData)
	if err != nil {
		result.State = "error"
		return result
	}

	buffer := make([]byte, 1024)

	//设置总超时
	deadline := time.Now().Add(timeout)

	for {
		// 设置读写超时
		conn.SetDeadline(time.Now().Add(200 * time.Millisecond))

		//总读取超时直接返回
		if time.Now().After(deadline) {
			// 超时，可能是开放或被过滤
			return result // 保持 open|filtered 状态
		}

		// 尝试接收UDP响应
		n, err := conn.Read(buffer)

		if err != nil {
			// 检查是否是超时错误
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				//短超时直接下一轮循环
				continue
			} else {
				result.State = "error"
				return result
			}
		} else {
			// 收到响应，端口开放
			if n > 0 {
				result.State = "open"
				//fmt.Printf("端口 %d 收到响应，长度: %d 字节\n", port, n)
				return result
			}
		}
	}
}

// 探测数据
func getProbeData(port int) []byte {
	switch port {
	case 53: // DNS
		return []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
			'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01,
		}
	case 111: // RPC portmap - 使用NULL调用
		return []byte{
			0x00, 0x00, 0x00, 0x00, // XID
			0x00, 0x00, 0x00, 0x00, // Message Type: Call (0)
			0x00, 0x00, 0x00, 0x02, // RPC Version: 2
			0x00, 0x00, 0x00, 0x00, // Program: 0 (NULL测试)
			0x00, 0x00, 0x00, 0x00, // Program Version: 0
			0x00, 0x00, 0x00, 0x00, // Procedure: NULL (0)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 123: // NTP
		return []byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 161: // SNMP
		return []byte{0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA0, 0x1C, 0x02, 0x04, 0x71, 0x97, 0x81, 0x75, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00}
	case 137: // NetBIOS Name Service
		return []byte{
			0x12, 0x34, // Transaction ID
			0x00, 0x00, // Flags: Query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			// Name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
			0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x00,
			0x00, 0x21, // Type: NBSTAT
			0x00, 0x01, // Class: IN
		}
	case 138: // NetBIOS Datagram Service
		return []byte{
			0x12, 0x34, // Transaction ID
			0x01, 0x10, // Flags: Response + Authoritative
			0x00, 0x01, // Questions: 1
			0x00, 0x01, // Answers: 1
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			// Query Name
			0x20, 0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x00,
			0x00, 0x21, // Type: NBSTAT
			0x00, 0x01, // Class: IN
		}
	case 1434: // SQL Server Resolution Protocol
		return []byte{0x02} // 最简单的探测包
	case 3306: // MySQL (UDP模式)
		return []byte{
			0x45, 0x00, 0x00, 0x40, // 基础MySQL握手探测
			0x00, 0x01, 0x00, 0x00,
			0x40, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
	case 5432: // PostgreSQL
		return []byte{
			0x00, 0x00, 0x00, 0x08, // Length: 8
			0x00, 0x03, 0x00, 0x00, // Cancel request
		}
	case 1900: // SSDP (Simple Service Discovery Protocol)
		return []byte("M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n")
	case 5353: // mDNS (Multicast DNS)
		return []byte{
			0x00, 0x00, // Transaction ID
			0x00, 0x00, // Flags: Query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			// _services._dns-sd._udp.local
			0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
			0x07, '_', 'd', 'n', 's', '-', 's', 'd',
			0x04, '_', 'u', 'd', 'p',
			0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
			0x00, 0x0C, // Type: PTR
			0x00, 0x01, // Class: IN
		}
	case 27015: // Steam
		return []byte{
			0xFF, 0xFF, 0xFF, 0xFF, // -1
			0x54,                                                                                                                   // 'T'
			0x53, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69, 0x6E, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00, // "Source Engine Query"
		}
	case 19132: // Minecraft
		return []byte{
			0x01,                                           // Packet ID: Unconnected Ping
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Magic
		}
	default:
		// 对于未知端口，发送多种通用探测数据
		if port < 1024 {
			// 系统服务端口，发送空包
			return []byte{}
		} else if port < 10000 {
			// 常见应用端口，发送HTTP-like探测
			return []byte("GET / HTTP/1.0\r\n\r\n")
		} else {
			// 高端口号，发送二进制探测
			return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
		}
	}
}
