package tcp_port

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yty0v0/ReconQuiver/internal/scanner"
)

// NULLScanResult 扫描结果
type NULLScanResult struct {
	Port   int
	State  string // "open|filtered", "closed", "error"
	Reason string
}

var nullResults []NULLScanResult

func Tcp_null(ip string, port []int, rate int) {
	timeout := 3 * time.Second
	start := time.Now()
	fmt.Printf("开始TCP NULL扫描 %s...\n", ip)

	NULLScan(ip, port, rate, timeout)

	fmt.Println("\n扫描结果:")
	fmt.Println("端口\t状态\t\t说明")
	fmt.Println("----\t----\t\t----")
	for _, result := range nullResults {
		fmt.Printf("%d\t%s\t%s\n", result.Port, result.State, result.Reason)
	}
	duration := time.Since(start)
	fmt.Println()
	fmt.Printf("扫描完成，耗时: %v\n", duration)
}

// NULLScan 执行TCP NULL扫描
func NULLScan(target string, ports []int, rate int, timeout time.Duration) {
	// 解析目标地址
	dstAddrs, err := net.LookupIP(target)
	if err != nil {
		fmt.Printf("DNS解析失败: %v\n", err)
		return
	}

	// 选择IPv4地址
	dstip, err := scanner.SelectIPv4(dstAddrs)
	if err != nil {
		fmt.Printf("未找到IPv4地址: %v\n", err)
		return
	}

	// 创建原始套接字（需要root权限）
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		fmt.Printf("创建原始套接字失败: %v\n", err)
		return
	}
	defer conn.Close()

	sem := make(chan struct{}, rate) // 设置并发控制

	// 扫描每个端口
	for _, port := range ports {
		scanner.Wg.Add(1)
		var result NULLScanResult
		go func(Port int) {
			sem <- struct{}{} // 获取一个许可
			defer scanner.Wg.Done()
			defer func() { <-sem }() // 使用函数结束时，许可被释放

			result.Port = Port

			// 发送NULL包并等待响应
			state, reason, err := scanPortWithNULL(conn, dstip, Port, timeout)
			if err != nil {
				result.State = "error"
				result.Reason = err.Error()
			} else {
				result.State = state
				result.Reason = reason
			}

			scanner.Mu.Lock()
			nullResults = append(nullResults, result)
			scanner.Mu.Unlock()

			// 避免过快扫描
			time.Sleep(100 * time.Millisecond)
		}(port)
	}
	scanner.Wg.Wait()
	return
}

// scanPortWithNULL 对单个端口进行NULL扫描
func scanPortWithNULL(conn net.PacketConn, dstip net.IP, port int, timeout time.Duration) (string, string, error) {
	// 获取本地IP和端口
	srcIp, srcPort, err := scanner.GetlocalIPPort(dstip.String())
	if err != nil {
		return "error", "获取本地IP失败", err
	}

	// 构造TCP/IP数据包
	packet, err := createNULLPacket(srcIp, dstip, srcPort, port)
	if err != nil {
		return "error", "构造数据包失败", err
	}

	// 发送NULL包
	if err := sendNULLPacket(conn, packet, dstip); err != nil {
		return "error", "发送数据包失败", err
	}

	// 监听响应
	return listenForNULLResponse(conn, srcPort, port, dstip, timeout)
}

// createNULLPacket 构造NULL数据包
func createNULLPacket(srcIP, dstip net.IP, srcPort, dstPort int) ([]byte, error) {
	// IP头部
	ip := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}

	// TCP头部（NULL扫描：所有标志位都为false）
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     scanner.GenerateRandomSeq(), // 随机序列号
		Window:  1024,
		// 注意：不设置SYN、ACK、FIN、RST等任何标志位
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

// sendNULLPacket 发送NULL数据包
func sendNULLPacket(conn net.PacketConn, packet []byte, dstip net.IP) error {
	_, err := conn.WriteTo(packet, &net.IPAddr{IP: dstip})
	return err
}

// listenForNULLResponse 监听并分析NULL扫描响应
func listenForNULLResponse(conn net.PacketConn, srcPort, dstPort int, dstip net.IP, timeout time.Duration) (string, string, error) {
	// 设置总超时
	deadline := time.Now().Add(timeout)

	buffer := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		// 检查是否超时
		if time.Now().After(deadline) {
			return "open|filtered", "超时无响应（端口可能开放或被防火墙过滤）", nil
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 短超时，继续等待直到总超时
				continue
			}
			return "error", "读取响应失败", err
		}

		// 检查响应来源
		if !addr.(*net.IPAddr).IP.Equal(dstip) {
			continue // 不是目标IP的响应
		}

		// 解析TCP包
		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// 验证端口匹配
			if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SrcPort == layers.TCPPort(dstPort) {
				if tcp.RST {
					return "closed", "收到RST响应（端口确定关闭）", nil
				} else {
					return "open|filtered", "收到非RST响应（端口可能开放）", nil
				}
			}
		}
	}
}
