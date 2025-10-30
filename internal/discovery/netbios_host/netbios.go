package netbios_host

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

type NetBIOSResult struct {
	IP      string
	Status  string // "alive", "filtered", "dead"
	Port137 string
}

func Netbios(ipaddres []string) {
	var results []NetBIOSResult
	fmt.Println("开始 NetBIOS 存活主机探测...")

	start := time.Now()

	// 阶段1: 主机发现（模仿nmap）
	fmt.Println("阶段1: 主机发现...")
	aliveHosts := hostDiscovery(ipaddres)
	fmt.Printf("发现 %d 个存活主机\n", len(aliveHosts))

	// 阶段2: NetBIOS扫描（只对存活主机）
	fmt.Println("阶段2: NetBIOS扫描...")
	sem := make(chan struct{}, 50)

	for _, ip := range aliveHosts {
		scanner.Wg.Add(1)
		go func(ip string) {
			defer scanner.Wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := netbiosProbe(ip)
			scanner.Mu.Lock()
			if result.Status != "dead" {
				results = append(results, result)
			}
			scanner.Mu.Unlock()
		}(ip)
	}
	scanner.Wg.Wait()

	// 输出结果
	if len(results) > 0 {
		fmt.Println("发现 NetBIOS 主机：")
		fmt.Println("IP地址\t\t状态\t\t137端口")
		for _, result := range results {
			fmt.Printf("%s\t%s\t%s\n",
				result.IP, result.Status, result.Port137)
		}
	} else {
		fmt.Println("未发现 NetBIOS 主机")
	}

	fmt.Printf("\n扫描完成，耗时: %v\n", time.Since(start))
	fmt.Printf("发现 %d 个 NetBIOS 主机\n", len(results))
}

// 主机发现 - 模仿nmap的-Pn扫描
func hostDiscovery(ips []string) []string {
	var aliveHosts []string
	sem := make(chan struct{}, 100)

	for _, ip := range ips {
		scanner.Wg.Add(1)
		go func(ip string) {
			defer scanner.Wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if isHostAlive(ip) {
				scanner.Mu.Lock()
				aliveHosts = append(aliveHosts, ip)
				scanner.Mu.Unlock()
			}
		}(ip)
	}
	scanner.Wg.Wait()

	return aliveHosts
}

// 主机存活检测
func isHostAlive(ip string) bool {
	// 使用nmap常用的端口进行主机发现
	ports := []int{80, 443, 22, 135, 139, 445, 21, 23, 53}

	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// NetBIOS探测 - 只对已知存活的主机进行
func netbiosProbe(ip string) NetBIOSResult {
	result := NetBIOSResult{
		IP:      ip,
		Status:  "dead",
		Port137: "关闭",
	}

	// UDP 137端口探测
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, 137), 3*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 发送查询
	query := createNetBIOSQuery()
	if _, err := conn.Write(query); err != nil {
		return result
	}

	// 接收响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// 已知存活的主机 + UDP超时 = open|filtered
			result.Status = "filtered"
			result.Port137 = "开放或被过滤"
		}
		return result
	}

	// 收到有效响应
	if n > 0 && validateNetBIOSResponse(buffer[:n]) {
		result.Status = "alive"
		result.Port137 = "开放"
	}

	return result
}

// 创建 NetBIOS 查询包
func createNetBIOSQuery() []byte {
	return []byte{
		0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}
}

// 验证 NetBIOS 响应
func validateNetBIOSResponse(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	return (flags & 0x8000) != 0
}
