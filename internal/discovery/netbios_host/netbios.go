package netbios_host

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

type NetBIOSResult struct {
	IP       string
	HostInfo string
	Status   string // "alive", "filtered", "dead"
	Reason   string
}

var results_netbios []NetBIOSResult //存储所有存活主机

func Netbios(ipaddres []string, rate int) {
	fmt.Println("开始 NetBIOS 服务探测...")
	fmt.Println("探测标准: UDP 137端口开放且NetBIOS服务开放")

	start := time.Now()

	//如果rate是默认值，则设置为并发50（并发50的结果更准确）
	if rate == 300 {
		rate = 50
	}
	sem := make(chan struct{}, rate)

	// 直接进行NetBIOS扫描
	for _, ip := range ipaddres {
		scanner.Wg.Add(1)
		go func(ip string) {
			defer scanner.Wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := netbiosProbe(ip)

			if result.Status == "alive" {

				result1 := NetBIOSResult{
					IP:       result.IP,
					HostInfo: "",
					Status:   result.Status,
					Reason:   result.Reason,
				}

				scanner.Mu.Lock()
				results_netbios = append(results_netbios, result1)
				scanner.Mu.Unlock()
			}
		}(ip)
	}
	scanner.Wg.Wait()

	//获取MAC地址
	var targetIps []string
	for _, result := range results_netbios {
		targetIps = append(targetIps, result.IP)
	}
	MacResult := scanner.GetMac(targetIps)

	//获取主机信息
	var datas []scanner.HostInfoResult //HostInfoResult在hostinfo代码里已经定义成全局变量
	for _, result := range results_netbios {
		data := scanner.HostInfoResult{
			IP:  result.IP,
			MAC: MacResult[result.IP],
		}
		datas = append(datas, data)
	}
	collector := scanner.NewHostInfo() //这一行确实已经调用了函数
	InfoResult := collector.GetHostInfoBatch(datas)

	// 输出结果
	if len(results_netbios) > 0 {
		fmt.Println("\nNetBIOS 服务发现：")
		//fmt.Println("IP地址\t\tMAC地址\t\t\t主机信息\t\t状态\t\t原因")
		for _, v := range results_netbios {
			//fmt.Printf("%s\t%s\t%s\t%s\t%s\n", v.IP, MacResult[v.IP], v.HostInfo, v.Status, v.Reason)

			fmt.Printf("IP地址:%s\n", v.IP)
			fmt.Printf("MAC地址:%s\n", MacResult[v.IP])
			fmt.Printf("主机信息:%s\n", InfoResult[v.IP])
			fmt.Printf("主机状态:%s\n", v.Status)
			fmt.Printf("存活原因:%s\n", v.Reason)
			fmt.Println()
		}
	} else {
		fmt.Println("未发现 NetBIOS 服务")
	}

	fmt.Printf("扫描完成，耗时: %v\n", time.Since(start))
	fmt.Printf("发现 %d 个 NetBIOS 服务\n", len(results_netbios))
}

// 使用 net.DialTimeout 方式的 NetBIOS 探测函数
func netbiosProbe(ip string) NetBIOSResult {
	result := NetBIOSResult{
		IP:     ip,
		Status: "dead",
		Reason: "无",
	}

	address := fmt.Sprintf("%s:%d", ip, 137)

	// 使用 net.DialTimeout 创建 UDP 连接
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()

	// 发送NetBIOS查询 - 使用 conn.Write()
	query := createNetBIOSQuery()
	n, err := conn.Write(query) // 直接使用 Write，因为目标地址在 Dial 时已指定
	if err != nil {
		result.Status = "filtered"
		result.Reason = "137端口开放但数据发送失败"
		return result
	}

	//设置总超时
	deadline := time.Now().Add(2 * time.Second)

	for {
		if time.Now().After(deadline) {
			return result
		}

		// 设置短超时
		conn.SetDeadline(time.Now().Add(300 * time.Millisecond))

		// 接收NetBIOS响应 - 使用 conn.Read()
		buffer := make([]byte, 1024)
		n, err = conn.Read(buffer) // 直接使用 Read，因为连接已建立
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue //短超时，继续监听
			} else {
				return result
			}
		}

		// 收到响应，验证NetBIOS协议
		if n > 0 {
			if validateNetBIOSResponse(buffer[:n]) {
				// UDP 137端口开放且NetBIOS服务开放
				result.Status = "alive"
				result.Reason = "137端口开放且有服务"
			} else {
				// UDP 137端口开放但不是NetBIOS服务
				return result
			}
		}
	}
	return result
}

// 创建 NetBIOS 名称查询包
func createNetBIOSQuery() []byte {
	return []byte{
		0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
		0x00, 0x01,
	}
}

// 改进的响应验证
func validateNetBIOSResponse(data []byte) bool {
	if len(data) < 12 {
		return false
	}

	// 检查响应标志位 (第3字节的最高位)
	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse := (flags & 0x8000) != 0

	// 检查答案数量
	answerCount := binary.BigEndian.Uint16(data[6:8])

	return isResponse && answerCount > 0
}
