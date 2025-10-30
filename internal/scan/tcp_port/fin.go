package tcp_port

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

func Tcp_fin(ip string, port []int, rate int) {
	start := time.Now()
	timeout := 4 * time.Second

	results := FINScan(ip, port, rate, timeout)

	fmt.Println("\n扫描结果:")
	fmt.Println("端口\t状态")
	fmt.Println("----\t----")
	for port, status := range results {
		fmt.Printf("%d\t%s\n", port, status)
	}

	duration := time.Since(start)
	fmt.Println()
	fmt.Printf("扫描完成，耗时: %v\n", duration)
}

// FINScan 执行TCP FIN扫描
func FINScan(targetIP string, ports []int, rate int, timeout time.Duration) map[int]string {
	results := make(map[int]string)
	sem := make(chan struct{}, rate) // 并发控制

	fmt.Printf("开始TCP FIN扫描 %s...\n", targetIP)

	for _, port := range ports {
		scanner.Wg.Add(1)
		go func(p int) {
			defer scanner.Wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			status, reason := scanPortWithFIN(targetIP, p, timeout)

			scanner.Mu.Lock()
			results[p] = fmt.Sprintf("%s (%s)", status, reason)
			scanner.Mu.Unlock()
		}(port)
	}

	scanner.Wg.Wait()
	return results
}

// scanPortWithFIN 对单个端口执行FIN扫描
func scanPortWithFIN(target string, targetPort int, timeout time.Duration) (string, string) {
	// 解析目标地址
	dstAddrs, err := net.LookupIP(target)
	if err != nil {
		return "error", "DNS解析失败"
	}

	// 选择IPv4地址
	dstIP, err := scanner.SelectIPv4(dstAddrs)
	if err != nil {
		return "error", "未找到IPV4地址"
	}

	// 获取本地IP和端口
	srcIP, srcPort, err := scanner.GetlocalIPPort(target)
	if err != nil {
		return "error", "获取本地地址失败"
	}

	// 创建原始套接字
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return "error", "创建原始套接字失败"
	}
	defer conn.Close()

	// 构造FIN数据包
	finPacket, err := createFINPacket(srcIP, srcPort, dstIP, targetPort)
	if err != nil {
		return "error", "构造FIN包失败"
	}

	// 发送FIN包
	if _, err := conn.WriteTo(finPacket, &net.IPAddr{IP: dstIP}); err != nil {
		return "error", "发送FIN包失败"
	}

	// 监听响应
	return listenForFINResponse(conn, srcPort, targetPort, dstIP, timeout)
}

// createFINPacket 构造TCP FIN数据包
func createFINPacket(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) ([]byte, error) {
	// IP层
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	// TCP层
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     true, // FIN标志置位
		Seq:     scanner.GenerateRandomSeq(),
	}

	// 设置校验和
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	// 序列化数据包
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// listenForFINResponse 监听FIN扫描响应
func listenForFINResponse(conn net.PacketConn, srcPort, dstPort int, dstIP net.IP, timeout time.Duration) (string, string) {
	deadline := time.Now().Add(timeout) //设置总超时

	buffer := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) // 设置读取超时
		if time.Now().After(deadline) {
			// 超时无响应 - 可能开放或被过滤
			return "open|filtered", "无响应（可能开放或被防火墙过滤）"
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // 短超时，继续等待
			}
			return "error", "读取响应失败"
		}

		// 检查响应来源
		respIP := addr.(*net.IPAddr).IP
		if !respIP.Equal(dstIP) {
			continue // 不是目标IP的响应
		}

		// 解析TCP包
		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// 验证端口匹配
			if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
				if tcp.RST {
					// 收到RST响应 - 端口关闭
					return "closed", "收到RST响应（端口关闭）"
				} else if tcp.SYN && tcp.ACK {
					// 收到SYN-ACK - 异常情况
					return "open", "收到SYN-ACK响应（端口开放）"
				}
				// 其他响应继续等待
			}
		}
	}
}
